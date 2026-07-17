<div align="center">
  <h1>📱 Remote Terminal Mirroring</h1>
  <p><b>A secure, native Windows alternative to tmux over Tailscale</b></p>
  
  [![Node.js](https://img.shields.io/badge/Node.js-16.0%2B-success.svg)](https://nodejs.org/)
  [![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)](https://microsoft.com/windows)
  [![Tailscale](https://img.shields.io/badge/Network-Tailscale-lightgrey.svg)](https://tailscale.com)
</div>

<br>

A secure, Node.js-based remote terminal mirroring application designed to run natively over Tailscale. It enables you to securely connect to and mirror your Windows terminal sessions from a mobile device or another computer within your private Tailnet.

## 🚀 Why `rterm`?
This architecture was specifically built to provide a **native Windows alternative to `tmux`**. While `tmux` requires running inside WSL on Windows, this application leverages a built-in session manager and the `rterm` CLI tool to provide the exact same terminal multiplexing capabilities directly on Windows. This allows you to open a regular Windows PowerShell, run a command, detach (<kbd>Ctrl</kbd> + <kbd>]</kbd>), and walk away—all while the session stays perfectly alive in the background and mirrors to your phone.

<br>

## ✨ Features

- 🔒 **Tailscale Integration:** Runs securely within your private Tailscale network (Tailnet).
- 🔑 **Strict OTP Authentication:** Uses a strictly single-use One-Time Password (OTP) for initial device pairing. The code self-destructs instantly after use, generating a cryptographically signed HMAC token for 12-hour background access.
- 💻 **Native Windows PTY:** Real-time terminal I/O streaming using native Windows PowerShell and `node-pty`. No WSL required!
- ⚡ **Global `rterm` CLI:** Start mirrored sessions instantly from any folder using the `rterm` command.
- 📜 **Scrollback History:** Features an in-memory 200KB scrollback buffer that retains thousands of lines of terminal history even if you refresh your mobile browser.
- 📱 **Mobile Swipe Gestures:** Optimized for mobile use with an innovative "Keyboard Mode" that maps touchscreen swipes to arrow keys (perfect for cycling command history).
- 🔄 **Multi-Session Support:** Attach to multiple mirrored sessions independently and view them side-by-side.

<br>

## 🛠 Prerequisites

- **OS:** Windows
- **Network:** [Tailscale](https://tailscale.com/) active on both host and connecting device
- **Node.js:** version 16.0.0 or higher
- **Build Tools:** Python and Visual Studio Build Tools (may be required to compile `node-pty` natively)

<br>

## 📦 Installation

<details open>
<summary><b>1. Clone & Install Dependencies</b></summary>
<br>

```bash
git clone <repository_url>
cd Remote-Terminal
npm install
```
</details>

<details open>
<summary><b>2. Install the global CLI</b></summary>
<br>

Link the package so you can use the `rterm` command from anywhere:
```bash
npm link
```
</details>

<details open>
<summary><b>3. Generate an SSL Certificate</b></summary>
<br>

Since the app uses secure WebSockets (`wss://`) and HTTPS, generate a self-signed certificate in the project root:
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
```
</details>

<br>

## 📖 Usage

### 1. Start the server
In your `Remote-Terminal` folder, run:
```bash
npm start
```

### 2. Pairing a Device
1. Look at the terminal output on your host to find the 6-digit **OTP AUTHENTICATION CODE**.
2. On your mobile device, navigate to `https://<laptop-tailscale-ip>:8443`.
3. Accept the browser's security warning (due to the self-signed certificate).
4. Enter the 6-digit OTP to pair your device.

> [!IMPORTANT]  
> For maximum security, the pairing code is strictly single-use. The moment you pair your device, the code self-destructs. If you need to pair a second device (like an iPad), type `show-otp` in the host terminal to reveal the newly generated code.

### 3. Creating a Mirrored Session
- Open a *new* Windows Terminal window anywhere on your PC.
- Run the command `rterm <session_name>` (e.g., `rterm myscript`).
- The session will immediately appear on your phone, and all input/output will be mirrored perfectly.
- You can also click the **New Terminal** button directly in the web UI.

### 4. Mobile Controls & Gestures
- **Scroll Mode (Default):** Swiping anywhere on the terminal smoothly scrolls up and down through your command history.
- **Keyboard Mode:** Tap the purple Floating Action Button (FAB) in the bottom right corner to activate Keyboard Mode. In this mode, scrolling is locked, and swipes are converted to arrow keys:
  - **Swipe Left / Right:** Moves the text cursor left or right.
  - **Swipe Up / Down:** Cycles through your previous terminal command history.
- **Virtual Keyboard:** Tapping the FAB also forces your phone's native virtual keyboard to pop up.

### 5. Managing Sessions
- **Detaching:** To close the terminal window on your laptop but leave the script running in the background, press <kbd>Ctrl</kbd> + <kbd>]</kbd>. The session will remain active and visible on your phone.
- **Deleting / Exiting:** To completely kill a session, just type `exit` inside the session and press Enter. 

<br>

## 🛡 Security & Troubleshooting

### Defense-in-Depth
To follow defense-in-depth security best practices, restrict port `8443` on your host to only accept connections from your specific device via Tailscale ACLs. Add a rule in your Tailscale Admin Console under `"acls"`:

```json
{
  "acls": [
    {
      "action": "accept",
      "src":    ["my-mobile-phone"],
      "dst":    ["my-laptop:8443"]
    }
  ]
}
```

### Revoking Access
- **Remote Revocation:** Tap the logout icon in the terminal UI or **Logout** on the session picker to instantly force-close connections on your device.
- **Local Revocation:** If you lose your device, type `revoke-all` in the host terminal running the server and press `Enter` to terminate all tokens and WebSockets globally.
- **Retrieving OTP:** Type `show-otp` in the host terminal and press `Enter` to display the active pairing code.

<br>

## 🤝 Contributing

We welcome contributions to make `rterm` even better! If you're interested in helping out, please follow these guidelines:

1. **Fork and Clone:** Fork the repository to your own GitHub account and clone it locally.
2. **Branching:** Create a new branch for your feature or bugfix (`git checkout -b feature/my-new-feature`).
3. **Commit Messages:** Write clear and descriptive commit messages.
4. **Testing:** Ensure your changes do not break existing PTY or WebSocket behavior. Test both the desktop and mobile browser experience.
5. **Pull Requests:** Open a Pull Request with a detailed description of what changes you made and why.

**Areas for Contribution:**
- Adding multi-user (tenant) support.
- Building a standalone Electron/Tauri desktop client.
- Creating native iOS/Android wrappers for better background processing.

<br>

## 📄 License
Refer to the `LICENSE` file for more details.