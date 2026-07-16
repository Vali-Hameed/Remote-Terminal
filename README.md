# Remote Terminal Mirroring

A secure, Node.js-based remote terminal mirroring application designed to run over Tailscale. It enables you to securely connect to and mirror your terminal sessions (like `tmux`) from a mobile device or another computer within your private Tailnet.

## Features

- **Tailscale Integration:** Runs securely within your private Tailscale network (Tailnet).
- **OTP Authentication:** Uses a One-Time Password (OTP) for initial device pairing, generating a cryptographically signed HMAC token for subsequent access.
- **WebSocket Terminal Stream:** Real-time terminal I/O streaming using `node-pty` and WebSockets.
- **Multi-Session Support:** Attach to multiple `tmux` sessions independently using a single pairing token and view them side-by-side in different browser tabs.
- **Access Revocation:** Supports both remote revocation (from the mobile device) and local recovery revocation (from the host).
- **Terminal Scrollback:** Full support for terminal scrollback history.

## Prerequisites

- **OS:** Linux, macOS, or WSL2 (Windows Subsystem for Linux). Native Windows command prompts are not fully supported by `node-pty` for Unix `tmux` workflows.
- **Build Tools:** `node-pty` requires native C/C++ bindings.
  - *Debian/Ubuntu/WSL2:* `sudo apt-get install build-essential python3`
  - *macOS:* `xcode-select --install`
- **Tailscale:** Active on both the host and the connecting device.
- **Node.js:** version 16.0.0 or higher.

## Installation

1. **Clone the repository and install dependencies:**
   ```bash
   npm install
   ```

2. **Generate an SSL Certificate:**
   Since the app uses secure WebSockets (`wss://`) and HTTPS, generate a self-signed certificate in the project root:
   ```bash
   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
   ```

## Security Best Practices

To follow defense-in-depth security best practices, restrict port `8443` on your host to only accept connections from your specific device via Tailscale ACLs. Add a rule in your Tailscale Admin Console under `"acls"`:

```json
{
  "acls": [
    {
      "action": "accept",
      "src":    ["my-mobile-phone"], // Replace with your phone's Tailscale device name
      "dst":    ["my-laptop:8443"]   // Replace with your laptop's Tailscale device name
    }
  ]
}
```

## Usage

1. **Start the server:**
   ```bash
   npm start
   ```

2. **Pairing a Device:**
   - Look at the terminal output on your host to find the 6-digit **OTP AUTHENTICATION CODE**.
   - On your mobile device, navigate to `https://<laptop-tailscale-ip>:8443`.
   - Accept the browser's security warning (due to the self-signed certificate).
   - Enter the 6-digit OTP to pair your device.

3. **Managing Sessions:**
   - Once paired, you'll see a list of active sessions.
   - Click the **New Tab** icon next to any session to open it in a new browser tab.
   - You can toggle between multiple `tmux` sessions side-by-side.

## Revoking Access

- **Remote Revocation:** Tap **Revoke** in the terminal UI or **Revoke Credentials** on the session picker to instantly force-close connections on your device.
- **Local Revocation:** If you lose your device, type `revoke-all` in the host terminal running the server and press `Enter` to terminate all tokens and WebSockets globally.

## License
Refer to the `LICENSE` file for more details.