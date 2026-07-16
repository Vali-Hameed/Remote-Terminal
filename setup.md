# Remote Terminal Mirroring Setup & Deployment Guide

This guide describes how to configure, run, and secure the remote terminal mirroring application. The application is built for Node.js, running securely within your private Tailnet.

---

## 1. Prerequisites

Since the application uses `node-pty` to run native terminal attachments, you need:
1. **Linux, macOS, or WSL2 (Windows Subsystem for Linux)**: Native Windows command prompts are not fully supported by `node-pty` for Unix `tmux` workflows. If you are on Windows, compile and execute the server within a WSL2 environment.
2. **Build Tools**: `node-pty` compiles native C/C++ bindings during installation. Ensure you have the required compilers:
   - **Debian/Ubuntu/WSL2**: `sudo apt-get install build-essential python3`
   - **macOS**: `xcode-select --install`
3. **Tailscale**: Ensure Tailscale is active and running on both your host laptop and your mobile device.

---

## 2. SSL Certificate Generation

To run WebSocket streams and secure HTTPS traffic within your Tailnet, you must generate a self-signed certificate. 

Run the following command in the project root directory (replace `100.x.y.z` with your actual laptop Tailscale IP if desired, or use standard localhost common name):

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
```

The server will automatically load `key.pem` and `cert.pem` from the root directory on startup.

---

## 3. Tailscale ACL Policy Configuration

To follow defense-in-depth security best practices, restrict port `8443` on your laptop to only accept incoming connections from your specific mobile phone device.

Open your **Tailscale Admin Console**, navigate to **Access Control (ACLs)**, and add a rule under `"acls"`:

```json
{
  "acls": [
    // Allow your mobile phone to access port 8443 on the host laptop
    {
      "action": "accept",
      "src":    ["my-mobile-phone"], // Replace with your phone's Tailscale device name or IP
      "dst":    ["my-laptop:8443"]   // Replace with your laptop's Tailscale device name
    }
  ]
}
```

This prevents other devices on your Tailnet (e.g. shared family devices or public servers) from connecting to the terminal mirroring port.

---

## 4. Run the Server & Locate the OTP

1. Install the npm packages:
   ```bash
   npm install
   ```
2. Start the server:
   ```bash
   npm start
   ```
3. Locate the printed **OTP pairing code** on your laptop terminal:
   ```text
   ================================================================
   [SERVER] Running securely over Tailscale at: https://100.115.92.14:8443
   [SERVER] WebSocket protocol active at: wss://100.115.92.14:8443
   ================================================================
   [SECURITY] OTP AUTHENTICATION CODE FOR PHONE PAIRING:
                  >>>  842917  <<<
   ================================================================
   ```

---

## 5. Usage & Multi-Session Mirroring

### Pairing the Phone
1. Open your mobile phone browser and navigate to the server's Tailscale URL: `https://<laptop-tailscale-ip>:8443`.
2. Accept the browser's security warning (since the SSL certificate is self-signed).
3. The **OTP entry screen** will load. Input the 6-digit code printed on your laptop terminal, and tap **Pair Device**.
4. Upon successful pairing, a cryptographically signed HMAC token is generated and saved locally in your phone's browser storage. You will be redirected to the **Active Sessions** list.

### Opening Multiple Sessions Side-by-Side
The application supports attaching to multiple tmux sessions independently using a single pairing token:
1. In the **Active Sessions** view, click the **New Tab** icon (square with arrow) next to any session.
2. This opens the session in a new browser tab.
3. The new tab reads the saved token from `localStorage`, authenticates automatically, and launches directly into that specific session's terminal mirror.
4. You can open multiple tabs on your phone, placing different tmux sessions side-by-side or toggling between them using browser tab navigation.

---

## 6. Access Revocation Channels

The system supports two independent revocation channels depending on where you are:

### A. Remote Revocation (From Mobile Phone)
If you are finished mirroring and want to log out your device:
1. Tap **Revoke** in the top bar of the terminal, or tap **Revoke Credentials** at the bottom of the session picker.
2. The server invalidates the token's nonce immediately.
3. Every browser tab using that token is instantly forced closed or redirected to the OTP pairing page.

### B. Local Recovery Revocation (From Host Laptop)
If you lose your phone or leave it unlocked:
1. Go to the terminal running the `server.js` application on your host laptop.
2. Type **`revoke-all`** and press **`Enter`**.
3. The server immediately clears all valid tokens in memory, terminates all active WebSockets, and kills all process wrapper attachments.
4. The system logs the following event:
   ```text
   [REVOCATION] Local admin command "revoke-all" received. Revoking all tokens...
   [REVOCATION] All connected sessions and access tokens successfully terminated.
   ```
