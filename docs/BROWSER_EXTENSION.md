# Pasha 2.0 — Browser Companion & Security Sentinel Extension

## 1. Overview & Purpose

The **Pasha Security Sentinel** is a lightweight, Manifest V3-compliant browser extension (compatible with Google Chrome, Microsoft Edge, Brave, and other Chromium browsers) that connects the user's browser session directly to the local **Pasha 2.0 Autonomic Security Engine**.

### Key Capabilities:
- **Real-Time Host Defense Posture**: Displays live host telemetry, snapshot counts, and defense status right in the browser toolbar.
- **Toolbar Threat Badges**: Background service worker polls local threat queues every minute via `chrome.alarms` and badges pending/queued threat counts in vibrant alert colors.
- **One-Click Security Scans**: Trigger full Windows security snapshots directly from the browser popup without opening a terminal.
- **Autonomous Threat Investigation**: Remotely dispatch pending candidates in the queue to Pasha's automated sandbox analysis engine.
- **Instant Console Launch**: Seamlessly transition from lightweight alerts to Pasha's deep forensic web console (`http://localhost:3000`).

---

## 2. Architecture & Design

```
+-------------------------------------------------------------------+
|               Chromium Browser (Chrome / Edge / Brave)             |
|                                                                   |
|   +--------------------------+      +-------------------------+   |
|   |  Toolbar Action & Badge  |      |   Background Worker     |   |
|   |  - Visual threat counter |<-----+   (service-worker.js)   |   |
|   |  - Alert color state     |      |   - Manifest V3 Alarms  |   |
|   +------------+-------------+      |   - Ephemeral Storage   |   |
|                |                    +------------+------------+   |
|                | Click                           |                |
|                v                                 | 60s Poll       |
|   +--------------------------+                   |                |
|   |    Popup UI (Thin UI)    |                   |                |
|   |  - Cyber Glassmorphism   |                   |                |
|   |  - Host Posture Card     |                   |                |
|   |  - Trigger Host Scan     |                   |                |
|   |  - Investigate Threats   |                   |                |
|   |  - Candidate Priority    |                   |                |
|   +------------+-------------+                   |                |
+----------------|---------------------------------|----------------+
                 | HTTP REST API                   |
                 v                                 v
+-------------------------------------------------------------------+
|           Local Pasha 2.0 Engine (http://127.0.0.1:8000)          |
|                                                                   |
|   - /api/agent/status              - /api/agent/scan              |
|   - /api/agent/candidates/summary  - /api/agent/investigate/next  |
|   - /api/agent/candidates          - /api/agent/diff/latest       |
+-------------------------------------------------------------------+
```

---

## 3. Directory Layout

The extension lives entirely in the `extension/` directory:

```
extension/
├── manifest.json         # Manifest V3 configuration & permissions
├── service-worker.js     # Background worker for polling & badge management
├── popup.html            # Dark cyber glassmorphic popup DOM
├── popup.css             # Neon cyan / cyber styling & micro-animations
├── popup.js              # Pure async event-driven popup controller
└── icons/
    ├── icon-16.png       # 16x16 px toolbar icon
    ├── icon-48.png       # 48x48 px extensions management icon
    └── icon-128.png      # 128x128 px Web Store / high-DPI display icon
```

---

## 4. Installation & Setup Instructions

### Step 1: Ensure Pasha Local Backend is Running
Ensure the FastAPI backend is listening on port 8000:
```powershell
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### Step 2: Load Unpacked in Chrome or Edge
1. Open Google Chrome (or Microsoft Edge).
2. In the URL address bar, enter:
   - For Chrome: `chrome://extensions`
   - For Edge: `edge://extensions`
3. Toggle the **Developer mode** switch in the top-right corner to **ON**.
4. Click the **Load unpacked** button in the top-left toolbar.
5. Browse and select the extension folder in this repo:
   ```
   c:\Users\quadr\Desktop\Pasha\Kashyap-Threat-Analyser\extension
   ```
6. The **Pasha Security Sentinel** extension will appear in your extensions list.
7. Click the **puzzle piece icon** in the browser toolbar and click the **Pin** icon next to *Pasha Security Sentinel* for 1-click access.

---

## 5. Security & Privacy Highlights

- **100% Localhost Sovereignty**: The extension communicates exclusively with `http://127.0.0.1:8000/*` and `http://localhost:8000/*`. No external network requests, analytics, or third-party telemetry are transmitted.
- **Strict Content Security Policy (CSP)**: Built cleanly under Manifest V3 without `eval()`, inline event handlers, or dynamic script injection.
- **Read-Only & Confirmed Actions**: The extension triggers read-only scans and sandbox investigations; remediation actions (process termination, quarantine) are strictly guarded and require manual user confirmation via the full web console.
