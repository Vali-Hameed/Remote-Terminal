// APPLICATION STATE
let socket = null;
let term = null;
let fitAddon = null;
let currentSessionId = null;
let isReconnecting = false;
let pingInterval = null;


// UI ELEMENTS
const authScreen = document.getElementById('auth-screen');
const pickerScreen = document.getElementById('picker-screen');
const terminalScreen = document.getElementById('terminal-screen');

const otpInput = document.getElementById('otp-input');
const authBtn = document.getElementById('auth-btn');
const sessionsList = document.getElementById('sessions-list');
const refreshBtn = document.getElementById('refresh-btn');
const logoutBtn = document.getElementById('logout-btn');
const newSessionBtn = document.getElementById('new-session-btn');

const termBackBtn = document.getElementById('term-back-btn');
const sessionTitle = document.getElementById('session-title');
const termNewTabBtn = document.getElementById('term-newtab-btn');
const termLogoutBtn = document.getElementById('term-logout-btn');

// NOTIFICATIONS
function showNotification(message, type = 'error') {
  const banner = document.getElementById('notification');
  const msgEl = document.getElementById('notification-message');
  
  banner.className = `notification ${type} show`;
  msgEl.textContent = message;
  
  setTimeout(() => {
    banner.classList.remove('show');
  }, 4000);
}

// ROUTING / VIEW TRANSITIONS
function showScreen(screenId) {
  authScreen.classList.remove('active');
  pickerScreen.classList.remove('active');
  terminalScreen.classList.remove('active');
  
  document.getElementById(screenId).classList.add('active');
  
  // Custom screen actions
  if (screenId === 'terminal-screen') {
    document.body.style.overflow = 'hidden';
    if (fitAddon) {
      setTimeout(() => fitAddon.fit(), 100);
    }
  } else {
    document.body.style.overflow = 'auto';
  }
}

// DETERMINE SERVER URL
function getWsUrl() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  // Default to the host serving the page. If loaded locally via file://, fallback to prompts.
  if (!window.location.host) {
    const ip = prompt("Enter your laptop's Tailscale IP address (e.g. 100.x.x.x):");
    return `${protocol}//${ip}:8443`;
  }
  return `${protocol}//${window.location.host}`;
}

// INITIALIZATION
window.addEventListener('DOMContentLoaded', () => {
  const params = new URLSearchParams(window.location.search);
  const targetSession = params.get('session');
  
  if (targetSession) {
    currentSessionId = targetSession;
  }
  
  connectWebSocket();
  
  // Setup button event listeners
  authBtn.addEventListener('click', handleOtpSubmit);
  otpInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleOtpSubmit();
  });
  
  refreshBtn.addEventListener('click', () => {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'list_sessions' }));
    }
  });
  
  if (newSessionBtn) {
    newSessionBtn.addEventListener('click', () => {
      if (socket && socket.readyState === WebSocket.OPEN) {
        const name = prompt("Enter a name for the new Windows session (leave blank for auto-generated):");
        if (name !== null) {
          socket.send(JSON.stringify({ type: 'create_session', sessionId: name.trim() }));
        }
      }
    });
  }
  
  logoutBtn.addEventListener('click', triggerLogout);
  termLogoutBtn.addEventListener('click', triggerLogout);
  
  termBackBtn.addEventListener('click', () => {
    disconnectTerminal();
    // Strip session query parameter from URL
    window.history.replaceState({}, document.title, window.location.pathname);
    showScreen('picker-screen');
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'list_sessions' }));
    }
  });

  termNewTabBtn.addEventListener('click', () => {
    if (currentSessionId) {
      window.open(`?session=${encodeURIComponent(currentSessionId)}`, '_blank');
    }
  });
});

// WEBSOCKET COMMUNICATION
function connectWebSocket() {
  const url = getWsUrl();
  console.log('Connecting to WebSocket at:', url);
  
  socket = new WebSocket(url);
  
  socket.onopen = () => {
    console.log('WebSocket connection opened.');
    isReconnecting = false;
    
    // Set up heartbeat keepalive
    clearInterval(pingInterval);
    pingInterval = setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: 'ping' }));
      }
    }, 30000);
    
    const savedToken = localStorage.getItem('remote_term_token');
    if (savedToken) {
      socket.send(JSON.stringify({ type: 'auth_token', token: savedToken }));
    } else {
      showScreen('auth-screen');
    }
  };
  
  socket.onmessage = (event) => {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch (err) {
      return;
    }
    
    switch (msg.type) {
      case 'auth_success':
        if (msg.token) {
          localStorage.setItem('remote_term_token', msg.token);
        }
        showNotification('Authenticated successfully', 'success');
        
        if (currentSessionId) {
          // If a query parameter targeted a session, attach immediately
          attachToSession(currentSessionId);
        } else {
          showScreen('picker-screen');
          socket.send(JSON.stringify({ type: 'list_sessions' }));
        }
        break;
        
      case 'sessions_list':
        renderSessions(msg.sessions);
        break;
        
      case 'session_created':
        showNotification('Session created.', 'success');
        if (msg.sessionId) {
          attachToSession(msg.sessionId);
        } else {
          socket.send(JSON.stringify({ type: 'list_sessions' }));
        }
        break;
        
      case 'pty_data':
        if (term) {
          term.write(msg.data);
        }
        break;
        
      case 'pty_exit':
        showNotification('PTY connection closed.', 'success');
        disconnectTerminal();
        showScreen('picker-screen');
        socket.send(JSON.stringify({ type: 'list_sessions' }));
        break;
        
      case 'revoked':
        showNotification(msg.message || 'Credentials revoked.', 'error');
        localStorage.removeItem('remote_term_token');
        disconnectTerminal();
        showScreen('auth-screen');
        break;
        
      case 'error':
        showNotification(msg.message, 'error');
        if (msg.message.includes('expired') || msg.message.includes('invalid')) {
          localStorage.removeItem('remote_term_token');
          showScreen('auth-screen');
        }
        break;
    }
  };
  
  socket.onclose = () => {
    console.log('WebSocket closed.');
    clearInterval(pingInterval);
    disconnectTerminal();
    
    if (!isReconnecting) {
      showNotification('Disconnected from server. Retrying...', 'error');
      isReconnecting = true;
      setTimeout(connectWebSocket, 3000);
    }
  };
  
  socket.onerror = (err) => {
    console.error('WebSocket error:', err);
  };
}

// HANDLERS
function handleOtpSubmit() {
  const otp = otpInput.value.trim();
  if (otp.length !== 6 || isNaN(otp)) {
    showNotification('Please enter a valid 6-digit code.', 'error');
    return;
  }
  
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: 'auth_otp', otp }));
  } else {
    showNotification('Not connected to laptop. Retrying connection...', 'error');
    connectWebSocket();
  }
}

function triggerLogout() {
  if (confirm('Are you sure you want to log out? This will revoke this token across all tabs.')) {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'revoke' }));
    } else {
      localStorage.removeItem('remote_term_token');
      showScreen('auth-screen');
    }
  }
}

function renderSessions(sessions) {
  sessionsList.innerHTML = '';
  
  if (!sessions || sessions.length === 0) {
    sessionsList.innerHTML = `
      <div class="empty-state">
        <p>No active Windows sessions found.</p>
        <p style="font-size: 12px; margin-top: 6px; color: var(--text-muted);">
          Click "New Terminal" to create one.
        </p>
      </div>
    `;
    return;
  }
  
  sessions.forEach(session => {
    const item = document.createElement('div');
    item.className = 'session-item';
    
    // Tap to attach in current tab
    item.addEventListener('click', (e) => {
      // Don't trigger if they clicked the new tab link button
      if (e.target.closest('.btn-tab-link')) return;
      attachToSession(session);
    });
    
    item.innerHTML = `
      <div class="session-info">
        <div class="session-icon">
          <svg width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>
        </div>
        <span class="session-name"></span>
      </div>
      <div class="session-actions">
        <button class="btn-tab-link" title="Open in new browser tab">
          <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"/></svg>
        </button>
      </div>
    `;
    
    // Safely set session name via textContent (prevents XSS)
    item.querySelector('.session-name').textContent = session;
    
    // Handle new tab link click
    const newTabBtn = item.querySelector('.btn-tab-link');
    newTabBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      window.open(`?session=${encodeURIComponent(session)}`, '_blank');
    });
    
    sessionsList.appendChild(item);
  });
}

// INTERACTIVE TERMINAL
function attachToSession(sessionId) {
  currentSessionId = sessionId;
  sessionTitle.textContent = sessionId;
  showScreen('terminal-screen');
  
  // Initialize Xterm.js
  const container = document.getElementById('terminal-container');
  container.innerHTML = ''; // clear
  
  term = new Terminal({
    cursorBlink: true,
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 14,
    scrollback: 5000,
    theme: {
      background: '#0c0914',
      foreground: '#f3f1f9',
      cursor: '#a855f7',
      selectionBackground: 'rgba(168, 85, 247, 0.25)',
      black: '#000000',
      red: '#ef4444',
      green: '#10b981',
      yellow: '#f59e0b',
      blue: '#3b82f6',
      magenta: '#a855f7',
      cyan: '#06b6d4',
      white: '#f3f1f9',
      brightBlack: '#4b5563',
      brightRed: '#ef4444',
      brightGreen: '#10b981',
      brightYellow: '#f59e0b',
      brightBlue: '#3b82f6',
      brightMagenta: '#a855f7',
      brightCyan: '#06b6d4',
      brightWhite: '#ffffff'
    }
  });
  
  fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(container);
  
  // Mobile touch scrolling via transparent overlay.
  const touchOverlay = document.createElement('div');
  touchOverlay.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;z-index:5;touch-action:none;';
  container.style.position = 'relative';
  container.appendChild(touchOverlay);
  
  let touchStartY = 0;
  let lastTouchY = 0;
  let lastTouchTime = 0;
  let touchAccumulator = 0;
  let velocityY = 0;
  let momentumRAF = null;
  let didSwipe = false;
  
  function scrollTerminal(linesToScroll) {
    if (!term) return;
    term.scrollLines(linesToScroll);
  }
  
  function stopMomentum() {
    if (momentumRAF) {
      cancelAnimationFrame(momentumRAF);
      momentumRAF = null;
    }
  }
  
  touchOverlay.addEventListener('touchstart', (e) => {
    if (e.touches.length === 1) {
      touchStartY = e.touches[0].clientY;
      lastTouchY = touchStartY;
      lastTouchTime = performance.now();
      touchAccumulator = 0;
      velocityY = 0;
      didSwipe = false;
      stopMomentum();
    }
  }, { passive: true });
  
  touchOverlay.addEventListener('touchmove', (e) => {
    if (e.touches.length !== 1 || !term) return;
    
    const currentY = e.touches[0].clientY;
    const diffY = lastTouchY - currentY;
    
    if (!didSwipe && Math.abs(currentY - touchStartY) > 10) {
      didSwipe = true;
    }
    
    if (didSwipe) {
      e.preventDefault();
    }
    
    const now = performance.now();
    const dt = now - lastTouchTime;
    
    if (dt > 0) {
      const instantV = diffY / dt;
      velocityY = velocityY * 0.6 + instantV * 0.4;
    }
    
    lastTouchY = currentY;
    lastTouchTime = now;
    
    touchAccumulator += diffY;
    const lineThreshold = 4;
    
    if (Math.abs(touchAccumulator) >= lineThreshold) {
      const lines = Math.trunc(touchAccumulator / lineThreshold);
      touchAccumulator = touchAccumulator % lineThreshold;
      scrollTerminal(lines);
    }
  }, { passive: false });
  
  touchOverlay.addEventListener('touchend', (e) => {
    // Basic momentum scrolling
    if (Math.abs(velocityY) > 0.08) {
      let v = velocityY;
      let acc = 0;
      let lastFrame = performance.now();
      
      function momentumFrame(now) {
        const elapsed = now - lastFrame;
        lastFrame = now;
        
        v *= 0.97;
        if (Math.abs(v) < 0.02) { momentumRAF = null; return; }
        
        acc += v * elapsed;
        const lineThreshold = 4;
        if (Math.abs(acc) >= lineThreshold) {
          const lines = Math.trunc(acc / lineThreshold);
          acc = acc % lineThreshold;
          scrollTerminal(lines);
        }
        momentumRAF = requestAnimationFrame(momentumFrame);
      }
      momentumRAF = requestAnimationFrame(momentumFrame);
    }
  });

  // Handle desktop clicks / normal taps on the overlay
  touchOverlay.addEventListener('click', (e) => {
    touchOverlay.style.pointerEvents = 'none';
    term.focus();
    // Attempt to click the element underneath (xterm's textarea)
    const el = document.elementFromPoint(e.clientX, e.clientY);
    if (el) el.click();
    setTimeout(() => { touchOverlay.style.pointerEvents = ''; }, 100);
  });

  // FAB Keyboard button click handler
  const fabKeyboard = document.getElementById('fab-keyboard');
  if (fabKeyboard) {
    fabKeyboard.addEventListener('click', () => {
      // Temporarily disable overlay so focus/clicks can pierce through
      touchOverlay.style.pointerEvents = 'none';
      term.focus();
      
      // Attempt to click the hidden textarea directly to force mobile keyboard
      const textarea = document.querySelector('.xterm-helper-textarea');
      if (textarea) textarea.click();
      
      setTimeout(() => { touchOverlay.style.pointerEvents = ''; }, 500);
    });
  }
  
  // Set initial dimensions and tell backend to attach
  fitAddon.fit();
  const dims = fitAddon.proposeDimensions() || { cols: 80, rows: 24 };
  
  socket.send(JSON.stringify({
    type: 'attach',
    sessionId,
    cols: dims.cols,
    rows: dims.rows
  }));
  
  // Pipe xterm input -> websocket
  term.onData(data => {
    // Send keyboard data to server
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'pty_input', data }));
    }
  });
  
  // Setup window resize listener
  window.addEventListener('resize', debouncedResize);
  if (window.visualViewport) {
    window.visualViewport.addEventListener('resize', debouncedResize);
  }
}

function disconnectTerminal() {
  window.removeEventListener('resize', debouncedResize);
  if (window.visualViewport) {
    window.visualViewport.removeEventListener('resize', debouncedResize);
  }
  
  if (term) {
    term.dispose();
    term = null;
  }
  fitAddon = null;
  currentSessionId = null;
}

// 120ms DEBOUNCED RESIZE HANDLER
let resizeTimeout = null;
function handleViewportResize() {
  if (!term || !fitAddon || !socket || socket.readyState !== WebSocket.OPEN) return;
  
  fitAddon.fit();
  const dims = fitAddon.proposeDimensions();
  
  if (dims && currentSessionId) {
    console.log(`[RESIZE] Resizing terminal to ${dims.cols}x${dims.rows} for session "${currentSessionId}"`);
    socket.send(JSON.stringify({
      type: 'resize',
      cols: dims.cols,
      rows: dims.rows
    }));
  }
}

function debouncedResize() {
  clearTimeout(resizeTimeout);
  resizeTimeout = setTimeout(handleViewportResize, 120);
}
