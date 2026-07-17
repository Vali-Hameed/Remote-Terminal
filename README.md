# Remote Terminal Mirroring

A secure, Node.js-based remote terminal mirroring application designed to run natively over Tailscale. It enables you to securely connect to and mirror your Windows terminal sessions from a mobile device or another computer within your private Tailnet.

## Why `rterm`?
This architecture was specifically built to provide a **native Windows alternative to `tmux`**. While `tmux` requires running inside WSL on Windows, this application leverages a built-in session manager and the `rterm` CLI tool to provide the exact same terminal multiplexing capabilities directly on Windows. This allows you to open a regular Windows PowerShell, run a command, detach (`Ctrl + ]`), and walk away—all while the session stays perfectly alive in the background and mirrors to your phone.

## Features

- **Tailscale Integration:** Runs securely within your private Tailscale network (Tailnet).
- **OTP Authentication:** Uses a One-Time Password (OTP) for initial device pairing, generating a cryptographically signed HMAC token for subsequent access.
- **Native Windows PTY:** Real-time terminal I/O streaming using native Windows PowerShell and `node-pty`. No WSL required!
- **Global `rterm` CLI:** Start mirrored sessions instantly from any folder using the `rterm` command.
- **Scrollback History:** Features an in-memory 200KB scrollback buffer that retains thousands of lines of terminal history even if you refresh your mobile browser.
- **Multi-Session Support:** Attach to multiple mirrored sessions independently and view them side-by-side.
- **Mobile Swipe Gestures:** Optimized for mobile use with an innovative "Keyboard Mode" that maps touchscreen swipes to arrow keys (perfect for cycling command history).
- **Access Revocation:** Supports both remote revocation (from the mobile device) and local recovery revocation (from the host).

## Prerequisites

- **OS:** Windows.
- **Tailscale:** Active on both the host and the connecting device.
- **Node.js:** version 16.0.0 or higher.
- **Build Tools:** `node-pty` may require Python and Visual Studio Build Tools to compile natively if pre-built binaries aren't available.

## Installation

1. **Clone the repository and install dependencies:**
   ```bash
   npm install
   ```

2. **Install the global CLI:**
   Link the package so you can use the `rterm` command anywhere:
   ```bash
   npm link
   ```

3. **Generate an SSL Certificate:**
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
   In your `Remote-Terminal` folder, run:
   ```bash
   npm start
   ```

2. **Pairing a Device:**
   - Look at the terminal output on your host to find the 6-digit **OTP AUTHENTICATION CODE**.
   - On your mobile device, navigate to `https://<laptop-tailscale-ip>:8443`.
   - Accept the browser's security warning (due to the self-signed certificate).
   - Enter the 6-digit OTP to pair your device.

3. **Creating a Mirrored Session:**
   - Open a *new* Windows Terminal window anywhere on your PC.
   - Run the command `rterm <session_name>` (e.g. `rterm myscript`).
   - The session will immediately appear on your phone, and all input/output will be mirrored perfectly.
   - You can also click the **New Terminal** button directly in the web UI.

4. **Mobile Controls & Gestures:**
   - **Scroll Mode (Default):** Swiping anywhere on the terminal smoothly scrolls up and down through your command history.
   - **Keyboard Mode:** Tap the purple Floating Action Button (FAB) in the bottom right corner to activate Keyboard Mode. In this mode, scrolling is locked, and swipes are converted to arrow keys:
     - **Swipe Left / Right:** Moves the text cursor left or right.
     - **Swipe Up / Down:** Cycles through your previous terminal command history.
   - **Virtual Keyboard:** Tapping the FAB also forces your phone's native virtual keyboard to pop up.

5. **Managing Sessions:**
   - **Detaching:** If you want to close the terminal window on your laptop but leave the script running in the background, press `Ctrl + ]`. The session will remain active and visible on your phone.
   - **Deleting / Exiting:** To completely kill a session and remove it from the active list, just type `exit` inside the session and press Enter. 

## Revoking Access & Troubleshooting

- **Remote Revocation:** Tap the logout icon in the terminal UI or **Logout** on the session picker to instantly force-close connections on your device.
- **Local Revocation:** If you lose your device, type `revoke-all` in the host terminal running the server and press `Enter` to terminate all tokens and WebSockets globally.
- **Retrieving OTP:** If your terminal has scrolled too far and you need the OTP pairing code again, type `show-otp` in the host terminal and press `Enter` to display the current active code.

## License
Refer to the `LICENSE` file for more details.