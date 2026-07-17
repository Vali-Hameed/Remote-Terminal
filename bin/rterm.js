#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const os = require('os');
const WebSocket = require('ws');

const args = process.argv.slice(2);
const sessionName = args[0];

if (!sessionName) {
  console.error('Usage: rterm <session_name>');
  process.exit(1);
}

const tokenPath = path.join(os.homedir(), '.remoteterm_token');
let adminToken;
try {
  adminToken = fs.readFileSync(tokenPath, 'utf8').trim();
} catch (err) {
  console.error('[ERROR] Could not read admin token. Make sure the Remote Terminal server is running (npm start).');
  process.exit(1);
}

function getTailscaleIp() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    const isTailscaleName = name.toLowerCase().includes('tailscale');
    for (const net of interfaces[name]) {
      if (net.family === 'IPv4') {
        const ip = net.address;
        const parts = ip.split('.').map(Number);
        const isTailscaleIp = parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127;
        
        if (isTailscaleName || isTailscaleIp) {
          return ip;
        }
      }
    }
  }
  return null;
}

const tailscaleIp = getTailscaleIp();
if (!tailscaleIp) {
  console.error('[ERROR] Tailscale IP not found. Ensure Tailscale is running.');
  process.exit(1);
}

const ws = new WebSocket(`wss://${tailscaleIp}:8443`, {
  rejectUnauthorized: false
});

let isAuthenticated = false;

ws.on('open', () => {
  ws.send(JSON.stringify({ type: 'auth_admin', token: adminToken }));
});

ws.on('message', (data) => {
  let msg;
  try {
    msg = JSON.parse(data);
  } catch (err) { return; }

  if (msg.type === 'auth_success') {
    isAuthenticated = true;
    
    // First try to create the session (in case it doesn't exist)
    ws.send(JSON.stringify({ 
      type: 'create_session', 
      sessionId: sessionName,
      cols: process.stdout.columns,
      rows: process.stdout.rows,
      cwd: process.cwd()
    }));

    // Then immediately try to attach
    ws.send(JSON.stringify({ 
      type: 'attach', 
      sessionId: sessionName 
    }));

    setupLocalTerminal();
  } else if (msg.type === 'pty_data') {
    process.stdout.write(msg.data);
  } else if (msg.type === 'pty_exit') {
    console.log('\r\n[Session exited]');
    cleanupAndExit(0);
  } else if (msg.type === 'error' && msg.message === 'Session name already exists.') {
    // Ignored, we just attach to it
  } else if (msg.type === 'error') {
    console.error('\r\n[SERVER ERROR]', msg.message);
  }
});

ws.on('close', () => {
  console.log('\r\n[Disconnected from server]');
  cleanupAndExit(0);
});

ws.on('error', (err) => {
  console.error('\r\n[WebSocket Error]', err.message || err);
  cleanupAndExit(1);
});

function setupLocalTerminal() {
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    
    process.stdin.on('data', (key) => {
      // Ctrl + ]  (ASCII 29 or 0x1d) -> Detach
      if (key === '\x1d') {
        console.log('\r\n[Detached from session]');
        cleanupAndExit(0);
      }
      
      // Send input to server
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'pty_input', data: key }));
      }
    });

    process.stdout.on('resize', () => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ 
          type: 'resize', 
          cols: process.stdout.columns,
          rows: process.stdout.rows 
        }));
      }
    });
  }
}

function cleanupAndExit(code) {
  if (process.stdin.isTTY) {
    process.stdin.setRawMode(false);
    process.stdin.pause();
  }
  process.exit(code);
}
