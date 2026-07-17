/**
 * REMOTE TERMINAL MIRRORING SERVER
 * 
 * ==========================================
 * THREAT MODEL & ACCEPTED RISKS
 * ==========================================
 * IN SCOPE:
 * - Opportunistic LAN Scanners: Mitigated by binding strictly to Tailscale IP interface and running over HTTPS/WSS.
 * - Lost/Unlocked Phone: Mitigated by 12h token expiry, a remote logout option, and a local stdin "revoke-all" console recovery path.
 * - Replay of Old Token: Mitigated by signing tokens with a transient, in-memory HMAC secret (regenerated on restart) and verifying nonces.
 * - Brute-forcing OTP: Mitigated by a strict 5-attempt, 15-minute cooldown rate-limiter per IP address.
 * 
 * OUT OF SCOPE (Accepted Risks):
 * - Compromised Tailscale Account: If an attacker has access to the user's Tailnet, they can reach the server port.
 * - Compromised Laptop OS: If the host machine is compromised, all session data and process structures are exposed.
 * - Dependency Supply-Chain: Relying on the npm packages 'ws' and 'node-pty' is an accepted risk.
 * 
 * NOTE: This is a single-user tool. There is no multi-tenant isolation.
 */

const https = require('https');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { exec } = require('child_process');
const WebSocket = require('ws');
const pty = require('node-pty');

// 1. CONSTANTS & SECURITY CONFIG
const PORT = 8443;
const OTP_ATTEMPT_LIMIT = 5;
const OTP_COOLDOWN_MS = 15 * 60 * 1000; // 15 minutes
const TOKEN_EXPIRY_MS = 12 * 60 * 60 * 1000; // 12 hours
const MAX_SESSIONS = 10;
const SESSION_NAME_REGEX = /^[a-zA-Z0-9_-]{1,64}$/;

// Regenerated each server restart, never persisted.
const hmacSecret = crypto.randomBytes(32);
let sessionOtp = crypto.randomInt(100000, 999999).toString();

// In-memory security and process stores
const activeNonces = new Set();
const otpAttempts = new Map(); // IP -> { count, cooldownUntil }
const activeSessions = new Map();  // sessionId -> ptyProcess
const scrollbackBuffers = new Map(); // sessionId -> string (max 200KB)

// CLI Admin Token
const adminToken = crypto.randomBytes(32).toString('hex');
const adminTokenPath = require('path').join(os.homedir(), '.remoteterm_token');
try {
  fs.writeFileSync(adminTokenPath, adminToken, { mode: 0o600 });
} catch (e) {
  console.warn('[WARNING] Failed to write .remoteterm_token. Local CLI client may not work.');
}

// 2. TAILSCALE BINDING CHECK
function getTailscaleIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    const isTailscaleName = name.toLowerCase().includes('tailscale');
    for (const net of interfaces[name]) {
      if (net.family === 'IPv4') {
        const ip = net.address;
        const parts = ip.split('.').map(Number);
        // Tailscale CGNAT range is 100.64.0.0/10 (100.64.0.0 - 100.127.255.255)
        const isTailscaleIp = parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127;
        
        if (isTailscaleName || isTailscaleIp) {
          return { name, ip };
        }
      }
    }
  }
  return null;
}

const tailscaleNet = getTailscaleIp();
if (!tailscaleNet) {
  console.error('================================================================');
  console.error('[CRITICAL ERROR] Tailscale interface or IP range not detected!');
  console.error('This server is designed for secure remote access over Tailscale.');
  console.error('Please ensure Tailscale is running and connected.');
  console.error('Available interfaces found:');
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    console.error(` - ${name}: ${ifaces[name].map(n => n.address).join(', ')}`);
  }
  console.error('================================================================');
  process.exit(1);
}

console.log(`[NETWORK] Found Tailscale interface: ${tailscaleNet.name} (${tailscaleNet.ip})`);

// 3. CRYPTOGRAPHIC UTILITIES
function safeCompare(input, target) {
  // Hash inputs using HMAC to ensure they are the same length before calling timingSafeEqual
  const hashInput = crypto.createHmac('sha256', hmacSecret).update(input).digest();
  const hashTarget = crypto.createHmac('sha256', hmacSecret).update(target).digest();
  return crypto.timingSafeEqual(hashInput, hashTarget);
}

function generateToken(nonce) {
  const payload = JSON.stringify({
    issuedAt: Date.now(),
    expiresAt: Date.now() + TOKEN_EXPIRY_MS,
    nonce
  });
  const payloadB64 = Buffer.from(payload).toString('base64url');
  const sig = crypto.createHmac('sha256', hmacSecret).update(payloadB64).digest('hex');
  return `${payloadB64}.${sig}`;
}

function verifyToken(tokenString) {
  if (!tokenString || typeof tokenString !== 'string') return null;
  const parts = tokenString.split('.');
  if (parts.length !== 2) return null;

  const [payloadB64, signature] = parts;
  const expectedSig = crypto.createHmac('sha256', hmacSecret).update(payloadB64).digest('hex');
  
  // Constant-time signature verification
  const sigValid = crypto.timingSafeEqual(
    Buffer.from(signature, 'hex'),
    Buffer.from(expectedSig, 'hex')
  );

  if (!sigValid) return null;

  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    if (Date.now() > payload.expiresAt) return null;
    if (!activeNonces.has(payload.nonce)) return null;
    return payload;
  } catch (err) {
    return null;
  }
}

// 4. SSL SETUP
let serverOptions;
try {
  const certPath = path.join(__dirname, '../certs/cert.pem');
  const keyPath = path.join(__dirname, '../certs/key.pem');
  serverOptions = {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath)
  };
} catch (err) {
  console.error('[CRITICAL ERROR] Failed to load SSL files (key.pem / cert.pem).');
  console.error('Please generate self-signed certificates. See setup.md for instructions.');
  process.exit(1);
}

// Create HTTPS Server
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src https://fonts.gstatic.com; connect-src 'self' wss:;"
};

const server = https.createServer(serverOptions, (req, res) => {
  const pathname = req.url.split('?')[0];
  console.log(`[HTTP] ${req.method} ${req.url} (Pathname: ${pathname}) from IP: ${req.socket.remoteAddress}`);
  
  // Apply security headers to all responses
  for (const [header, value] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(header, value);
  }
  
  if (pathname === '/' || pathname === '/index.html') {
    fs.readFile(path.join(__dirname, '../public/index.html'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading index.html');
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(data);
      }
    });
  } else if (pathname === '/js/app.js') {
    fs.readFile(path.join(__dirname, '../public/js/app.js'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading app.js');
      } else {
        res.writeHead(200, { 'Content-Type': 'application/javascript' });
        res.end(data);
      }
    });
  } else if (pathname === '/css/style.css') {
    fs.readFile(path.join(__dirname, '../public/css/style.css'), (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading style.css');
      } else {
        res.writeHead(200, { 'Content-Type': 'text/css' });
        res.end(data);
      }
    });
  } else {
    res.writeHead(403);
    res.end('Forbidden');
  }
});

// Create WebSocket Server
const wss = new WebSocket.Server({ server });

// 5. LOCAL REVOCATION CHANNEL (STDIN)
process.stdin.setEncoding('utf8');
process.stdin.on('data', (data) => {
  const command = data.trim();
  if (command === 'revoke-all') {
    console.log('\n[REVOCATION] Local admin command "revoke-all" received. Revoking all tokens immediately...');
    
    // Clear in-memory token list
    activeNonces.clear();
    
    // Terminate all WebSocket connections
    for (const client of wss.clients) {
      try {
        client.send(JSON.stringify({ type: 'revoked', message: 'All tokens revoked by host system.' }));
        client.close();
      } catch (err) {
        // Socket may already be dead
      }
    }
    
    // Terminate all sessions
    for (const [sessionId, ptyProcess] of activeSessions.entries()) {
      try {
        ptyProcess.kill();
      } catch (err) {
        // Process may already be dead
      }
    }
    activeSessions.clear();
    scrollbackBuffers.clear();
    console.log('[REVOCATION] All connected sessions and access tokens successfully terminated.');
  } else if (command === 'show-otp') {
    console.log(`\n[AUTH] Current Remote Pairing Code (OTP): ${sessionOtp}\n`);
  } else if (command) {
    console.log(`[CLI] Unknown command: "${command}". Available commands: show-otp, revoke-all`);
  }
});

// 6. CLIENT WEB SOCKET HANDLER
wss.on('connection', (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  console.log(`[WS] Connection opened from ${clientIp}`);

  ws.isAuthenticated = false;
  ws.authNonce = null;
  ws.attachedSessionId = null;
  ws.ptyProcess = null;

  // Connection gating: Authentication timeout (5 seconds to prove identity)
  const authTimeout = setTimeout(() => {
    if (!ws.isAuthenticated) {
      console.log(`[WS] Closing connection from ${clientIp} due to authentication timeout.`);
      ws.close();
    }
  }, 5000);

  ws.on('message', (messageBuffer) => {
    let message;
    try {
      message = JSON.parse(messageBuffer.toString());
    } catch (err) {
      return;
    }

    // A. PAIRING FLOW (OTP authentication)
    if (message.type === 'auth_otp') {
      const now = Date.now();
      const ipLimiter = otpAttempts.get(clientIp) || { count: 0, cooldownUntil: 0 };

      if (ipLimiter.cooldownUntil && now < ipLimiter.cooldownUntil) {
        const remaining = Math.ceil((ipLimiter.cooldownUntil - now) / 1000);
        ws.send(JSON.stringify({ type: 'error', message: `Rate limit active. Try again in ${remaining} seconds.` }));
        return;
      }

      const inputOtp = String(message.otp || '');
      const isOtpValid = safeCompare(inputOtp, sessionOtp);

      if (isOtpValid) {
        // Reset rate limiter, clear auth timeout
        otpAttempts.delete(clientIp);
        clearTimeout(authTimeout);

        // Generate token and record active nonce
        const nonce = crypto.randomBytes(16).toString('hex');
        activeNonces.add(nonce);
        const token = generateToken(nonce);

        ws.isAuthenticated = true;
        ws.authNonce = nonce;

        console.log(`[AUTH] Successful OTP pairing. Issued token for IP: ${clientIp}`);
        
        // Consume and regenerate the OTP for strict one-time use
        sessionOtp = crypto.randomInt(100000, 999999).toString();
        console.log(`[AUTH] OTP consumed and regenerated for security. Use 'show-otp' to retrieve the new code if pairing another device.`);

        ws.send(JSON.stringify({ type: 'auth_success', token }));
      } else {
        // Increment attempts
        ipLimiter.count += 1;
        if (ipLimiter.count >= OTP_ATTEMPT_LIMIT) {
          ipLimiter.cooldownUntil = now + OTP_COOLDOWN_MS;
          console.warn(`[SECURITY] OTP lockout triggered for client IP: ${clientIp}`);
        }
        otpAttempts.set(clientIp, ipLimiter);
        
        ws.send(JSON.stringify({ type: 'error', message: 'Authentication failed.' }));
        ws.close();
      }
      return;
    }

    // B. RECONNECTION FLOW (Token authentication)
    if (message.type === 'auth_token') {
      const token = String(message.token || '');
      const payload = verifyToken(token);

      if (payload) {
        clearTimeout(authTimeout);
        ws.isAuthenticated = true;
        ws.authNonce = payload.nonce;

        console.log(`[AUTH] Successful token reconnection for IP: ${clientIp}`);
        ws.send(JSON.stringify({ type: 'auth_success' }));
      } else {
        console.warn(`[SECURITY] Refused invalid or expired token from IP: ${clientIp}`);
        ws.send(JSON.stringify({ type: 'error', message: 'Authentication token invalid or expired.' }));
        ws.close();
      }
      return;
    }

    // B2. CLI ADMIN AUTHENTICATION
    if (message.type === 'auth_admin') {
      const token = String(message.token || '');
      // Hash to prevent timing attacks, though it's local
      const isTokenValid = crypto.timingSafeEqual(
        crypto.createHash('sha256').update(token).digest(),
        crypto.createHash('sha256').update(adminToken).digest()
      );

      if (isTokenValid) {
        clearTimeout(authTimeout);
        ws.isAuthenticated = true;
        // Admin connections don't use nonces since they are strictly local and don't get revoked by remote phone actions
        ws.isAdmin = true;
        console.log(`[AUTH] Successful CLI admin connection for IP: ${clientIp}`);
        ws.send(JSON.stringify({ type: 'auth_success' }));
      } else {
        console.warn(`[SECURITY] Refused invalid admin token from IP: ${clientIp}`);
        ws.send(JSON.stringify({ type: 'error', message: 'Admin token invalid.' }));
        ws.close();
      }
      return;
    }

    // =========================================================================
    // CRITICAL SECURITY ENFORCEMENT POINT
    // No message below this comment block can be executed without verifying:
    // 1. Connection is authenticated (ws.isAuthenticated).
    // 2. The authentication token nonce exists in the active (non-revoked) set (or it's an admin).
    // =========================================================================
    if (!ws.isAuthenticated || (!ws.isAdmin && !activeNonces.has(ws.authNonce))) {
      console.warn(`[SECURITY] Unauthenticated action request from ${clientIp}. Terminating connection.`);
      ws.close();
      return;
    }

    // C. SESSION DISCOVERY
    if (message.type === 'list_sessions') {
      const sessions = Array.from(activeSessions.keys());
      ws.send(JSON.stringify({ type: 'sessions_list', sessions }));
      return;
    }

    // C2. SESSION CREATION
    if (message.type === 'create_session') {
      const targetSessionId = message.sessionId || `session_${crypto.randomBytes(4).toString('hex')}`;
      
      // Validate session name
      if (!SESSION_NAME_REGEX.test(targetSessionId)) {
        ws.send(JSON.stringify({ type: 'error', message: 'Invalid session name. Use only letters, numbers, dashes, and underscores (max 64 chars).' }));
        return;
      }
      
      if (activeSessions.has(targetSessionId)) {
        ws.send(JSON.stringify({ type: 'error', message: 'Session name already exists.' }));
        return;
      }

      // Enforce session cap
      if (activeSessions.size >= MAX_SESSIONS) {
        ws.send(JSON.stringify({ type: 'error', message: `Maximum session limit (${MAX_SESSIONS}) reached. Close an existing session first.` }));
        return;
      }

      // Validate cwd: must exist and be under user profile
      const userProfile = process.env.USERPROFILE || process.env.HOME || '';
      let safeCwd = userProfile;
      if (message.cwd) {
        const path = require('path');
        const resolvedCwd = path.resolve(message.cwd);
        try {
          const stat = fs.statSync(resolvedCwd);
          if (stat.isDirectory() && resolvedCwd.toLowerCase().startsWith(userProfile.toLowerCase())) {
            safeCwd = resolvedCwd;
          } else {
            console.warn(`[SECURITY] Blocked cwd "${resolvedCwd}" (not under user profile). Falling back to home.`);
          }
        } catch (e) {
          console.warn(`[SECURITY] Blocked cwd "${resolvedCwd}" (does not exist). Falling back to home.`);
        }
      }

      console.log(`[PTY] Spawning new native Windows session "${targetSessionId}" for IP: ${clientIp}`);
      
      try {
        const isWin = process.platform === 'win32';
        const shell = isWin ? 'powershell.exe' : 'bash';
        
        const ptyProcess = pty.spawn(shell, [], {
          name: 'xterm-256color',
          cols: message.cols || 80,
          rows: message.rows || 24,
          cwd: safeCwd,
          env: process.env
        });

        activeSessions.set(targetSessionId, ptyProcess);

        // Pipe PTY output to all attached clients and maintain scrollback buffer
        ptyProcess.onData((data) => {
          let buf = (scrollbackBuffers.get(targetSessionId) || '') + data;
          if (buf.length > 200000) {
            buf = buf.substring(buf.length - 200000);
          }
          scrollbackBuffers.set(targetSessionId, buf);
          
          for (const client of wss.clients) {
            if (client.attachedSessionId === targetSessionId && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ type: 'pty_data', data }));
            }
          }
        });

        ptyProcess.onExit(({ exitCode }) => {
          console.log(`[PTY] Session "${targetSessionId}" exited (Code: ${exitCode}).`);
          activeSessions.delete(targetSessionId);
          scrollbackBuffers.delete(targetSessionId);
          for (const client of wss.clients) {
            if (client.attachedSessionId === targetSessionId && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({ type: 'pty_exit' }));
              client.attachedSessionId = null;
            }
          }
        });

        // Tell client to refresh list
        ws.send(JSON.stringify({ type: 'session_created', sessionId: targetSessionId }));

      } catch (ptyErr) {
        console.error('[PTY] Error spawning pseudo-terminal:', ptyErr);
        ws.send(JSON.stringify({ type: 'error', message: 'Failed to create session.' }));
      }
      return;
    }

    // D. SESSION ATTACHMENT
    if (message.type === 'attach') {
      const targetSessionId = String(message.sessionId || '');

      // CRITICAL ALLOWLIST CHECK: Reject input if it is not on the active sessions list
      if (!activeSessions.has(targetSessionId)) {
        console.warn(`[SECURITY] Blocked unauthorized attach attempt to session "${targetSessionId}" from IP ${clientIp}`);
        ws.send(JSON.stringify({ type: 'error', message: 'Session ID is invalid or not running.' }));
        return;
      }

      ws.attachedSessionId = targetSessionId;
      console.log(`[PTY] Client ${clientIp} attached to session "${targetSessionId}"`);

      // Replay scrollback buffer so the client sees history on refresh/connect
      const scrollback = scrollbackBuffers.get(targetSessionId) || '';
      if (scrollback) {
        ws.send(JSON.stringify({ type: 'pty_data', data: scrollback }));
      } else {
        ws.send(JSON.stringify({ type: 'pty_data', data: '\r\n[Attached to session: ' + targetSessionId + ']\r\n' }));
      }
      return;
    }

    // E. INPUT INJECTION (PTY write)
    if (message.type === 'pty_input') {
      if (ws.attachedSessionId && activeSessions.has(ws.attachedSessionId)) {
        activeSessions.get(ws.attachedSessionId).write(message.data);
      }
      return;
    }

    // F. TERMINAL RESIZE
    if (message.type === 'resize') {
      if (ws.attachedSessionId && activeSessions.has(ws.attachedSessionId)) {
        const cols = parseInt(message.cols);
        const rows = parseInt(message.rows);
        if (!isNaN(cols) && !isNaN(rows) && cols > 0 && rows > 0) {
          activeSessions.get(ws.attachedSessionId).resize(cols, rows);
        }
      }
      return;
    }

    // G. REMOTE REVOCATION (Logout device)
    if (message.type === 'revoke') {
      const nonceToRevoke = ws.authNonce;
      console.log(`[REVOCATION] Remote revocation request for token nonce: ${nonceToRevoke} from IP: ${clientIp}`);

      // De-authenticate token nonce
      activeNonces.delete(nonceToRevoke);

      // Force-close all sockets matching the nonce
      for (const client of wss.clients) {
        if (client.authNonce === nonceToRevoke) {
          try {
            client.send(JSON.stringify({ type: 'revoked', message: 'Logged out from device.' }));
            client.close();
          } catch (err) {
            // Ignore
          }
        }
      }
      return;
    }
  });

  ws.on('close', () => {
    console.log(`[WS] Connection closed from ${clientIp}`);
    cleanupPtyConnection(ws);
  });

  ws.on('error', (err) => {
    console.error(`[WS] Connection error from ${clientIp}:`, err);
    cleanupPtyConnection(ws);
  });
});

function cleanupPtyConnection(ws) {
  ws.attachedSessionId = null;
}

// 7. START SERVER
server.listen(PORT, tailscaleNet.ip, () => {
  console.log('================================================================');
  console.log(`[SERVER] Running securely over Tailscale at: https://${tailscaleNet.ip}:${PORT}`);
  console.log(`[SERVER] WebSocket protocol active at: wss://${tailscaleNet.ip}:${PORT}`);
  console.log('================================================================');
  console.log(`[SECURITY] OTP AUTHENTICATION CODE FOR PHONE PAIRING:`);
  console.log(`               >>>  ${sessionOtp}  <<<`);
  console.log('================================================================');
  console.log('[CONSOLE] Type "revoke-all" and press Enter to instantly revoke');
  console.log('          all active tokens and disconnect all connections.');
  console.log('================================================================');
});
