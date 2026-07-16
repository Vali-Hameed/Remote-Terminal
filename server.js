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

// Regenerated each server restart, never persisted.
const hmacSecret = crypto.randomBytes(32);
const sessionOtp = crypto.randomInt(100000, 999999).toString();

// In-memory security and process stores
const activeNonces = new Set();
const otpAttempts = new Map(); // IP -> { count, cooldownUntil }
const activePtys = new Map();  // sessionId -> Set(ptyProcess)

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
  serverOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
  };
} catch (err) {
  console.error('[CRITICAL ERROR] Failed to load SSL files (key.pem / cert.pem).');
  console.error('Please generate self-signed certificates. See setup.md for instructions.');
  process.exit(1);
}

// Create HTTPS Server
const server = https.createServer(serverOptions, (req, res) => {
  const pathname = req.url.split('?')[0];
  console.log(`[HTTP] ${req.method} ${req.url} (Pathname: ${pathname}) from IP: ${req.socket.remoteAddress}`);
  if (pathname === '/' || pathname === '/index.html') {
    fs.readFile('index.html', (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading index.html');
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(data);
      }
    });
  } else if (pathname === '/app.js') {
    fs.readFile('app.js', (err, data) => {
      if (err) {
        res.writeHead(500);
        res.end('Error loading app.js');
      } else {
        res.writeHead(200, { 'Content-Type': 'application/javascript' });
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
    
    // Terminate all spawned PTY wrappers (tmux sessions remain active, only attachment layers die)
    for (const [sessionId, ptySet] of activePtys.entries()) {
      for (const ptyProcess of ptySet) {
        try {
          ptyProcess.kill();
        } catch (err) {
          // Process may already be dead
        }
      }
    }
    activePtys.clear();
    console.log('[REVOCATION] All connected sessions and access tokens successfully terminated.');
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

    // =========================================================================
    // CRITICAL SECURITY ENFORCEMENT POINT
    // No message below this comment block can be executed without verifying:
    // 1. Connection is authenticated (ws.isAuthenticated).
    // 2. The authentication token nonce exists in the active (non-revoked) set.
    // =========================================================================
    if (!ws.isAuthenticated || !activeNonces.has(ws.authNonce)) {
      console.warn(`[SECURITY] Unauthenticated action request from ${clientIp}. Terminating connection.`);
      ws.close();
      return;
    }

    // C. SESSION DISCOVERY
    if (message.type === 'list_sessions') {
      const tmuxCmd = process.platform === 'win32' ? 'wsl tmux' : 'tmux';
      // Execute tmux list-sessions safely (we don't interpolate client input here)
      exec(`${tmuxCmd} list-sessions`, (err, stdout, stderr) => {
        const sessions = [];
        if (!err && stdout) {
          const lines = stdout.split('\n');
          for (const line of lines) {
            // Match session name. Format example: "my-session: 2 windows (created Thu Jul 16 ...)"
            const match = line.match(/^([^:]+):/);
            if (match) {
              sessions.push(match[1]);
            }
          }
        }
        
        // Respond with tmux sessions. Do not leak raw errors or stderr to client
        ws.send(JSON.stringify({ type: 'sessions_list', sessions }));
      });
      return;
    }

    // D. SESSION ATTACHMENT
    if (message.type === 'attach') {
      const targetSessionId = String(message.sessionId || '');
      const tmuxCmd = process.platform === 'win32' ? 'wsl tmux' : 'tmux';

      // Verify session list first to enforce allowlist validation
      exec(`${tmuxCmd} list-sessions`, (err, stdout, stderr) => {
        const allowedSessions = [];
        if (!err && stdout) {
          const lines = stdout.split('\n');
          for (const line of lines) {
            const match = line.match(/^([^:]+):/);
            if (match) {
              allowedSessions.push(match[1]);
            }
          }
        }

        // CRITICAL ALLOWLIST CHECK: Reject input if it is not on the active tmux sessions list
        if (!allowedSessions.includes(targetSessionId)) {
          console.warn(`[SECURITY] Blocked unauthorized attach attempt to session "${targetSessionId}" from IP ${clientIp}`);
          ws.send(JSON.stringify({ type: 'error', message: 'Session ID is invalid or not running.' }));
          return;
        }

        // If client was already attached to a pty, clean it up first
        if (ws.ptyProcess) {
          cleanupPtyConnection(ws);
        }

        console.log(`[PTY] Spawning attachment process for session "${targetSessionId}" for IP: ${clientIp}`);
        
        try {
          // Spawn the pty wrapper using node-pty. Run in tmux attach mode.
          const isWin = process.platform === 'win32';
          const wslPath = isWin ? `${process.env.SystemRoot || 'C:\\Windows'}\\System32\\wsl.exe` : '';
          const ptyProcess = pty.spawn(
            isWin ? wslPath : 'tmux',
            isWin ? ['tmux', 'attach-session', '-t', targetSessionId] : ['attach-session', '-t', targetSessionId],
            {
              name: 'xterm-256color',
              cols: message.cols || 80,
              rows: message.rows || 24,
              cwd: process.env.HOME || process.env.USERPROFILE || '.',
              env: process.env
            }
          );

          ws.ptyProcess = ptyProcess;
          ws.attachedSessionId = targetSessionId;

          // Track in activePtys Map
          if (!activePtys.has(targetSessionId)) {
            activePtys.set(targetSessionId, new Set());
          }
          activePtys.get(targetSessionId).add(ptyProcess);

          // Pipe PTY output to client WebSocket
          ptyProcess.onData((data) => {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'pty_data', data }));
            }
          });

          ptyProcess.onExit(({ exitCode, signal }) => {
            console.log(`[PTY] Session "${targetSessionId}" attachment process exited (Code: ${exitCode}).`);
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ type: 'pty_exit' }));
            }
            cleanupPtyConnection(ws);
          });

        } catch (ptyErr) {
          console.error('[PTY] Error spawning pseudo-terminal:', ptyErr);
          ws.send(JSON.stringify({ type: 'error', message: 'Failed to initialize terminal interface.' }));
        }
      });
      return;
    }

    // E. INPUT INJECTION (PTY write)
    if (message.type === 'pty_input') {
      if (ws.ptyProcess) {
        ws.ptyProcess.write(message.data);
      }
      return;
    }

    // F. TERMINAL RESIZE
    if (message.type === 'resize') {
      if (ws.ptyProcess) {
        const cols = parseInt(message.cols);
        const rows = parseInt(message.rows);
        if (!isNaN(cols) && !isNaN(rows) && cols > 0 && rows > 0) {
          // Resize only this specific client's node-pty process.
          ws.ptyProcess.resize(cols, rows);
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
  if (ws.ptyProcess) {
    const ptyProcess = ws.ptyProcess;
    const sessionId = ws.attachedSessionId;
    ws.ptyProcess = null;
    ws.attachedSessionId = null;

    try {
      ptyProcess.kill();
    } catch (err) {
      // already terminated
    }

    // Remove from tracking Map
    if (sessionId && activePtys.has(sessionId)) {
      const ptySet = activePtys.get(sessionId);
      ptySet.delete(ptyProcess);
      if (ptySet.size === 0) {
        activePtys.delete(sessionId);
      }
    }
  }
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
