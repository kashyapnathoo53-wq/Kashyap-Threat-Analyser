/**
 * Pasha Security Sentinel - Popup Interface Controller
 * Manifest V3 Compliant - pure async event-driven architecture
 */

const API_BASE = "http://127.0.0.1:8000";
const WEB_DASHBOARD_URL = "http://localhost:3000";

// DOM Elements
const connectionStatus = document.getElementById("connectionStatus");
const statusDot = connectionStatus.querySelector(".dot");
const statusText = connectionStatus.querySelector(".status-text");
const offlineBanner = document.getElementById("offlineBanner");
const refreshBtn = document.getElementById("refreshBtn");

const machineIdEl = document.getElementById("machineId");
const hostPostureEl = document.getElementById("hostPosture");
const snapshotCountEl = document.getElementById("snapshotCount");
const threatQueueCountEl = document.getElementById("threatQueueCount");
const threatBadgeEl = document.getElementById("threatBadge");
const candidatesListEl = document.getElementById("candidatesList");
const lastUpdatedEl = document.getElementById("lastUpdated");

const scanHostBtn = document.getElementById("scanHostBtn");
const scanSpinner = document.getElementById("scanSpinner");
const investigateBtn = document.getElementById("investigateBtn");
const invSpinner = document.getElementById("invSpinner");
const openDashboardBtn = document.getElementById("openDashboardBtn");
const toastEl = document.getElementById("toast");

// Initialize Popup
document.addEventListener("DOMContentLoaded", async () => {
  setupEventListeners();
  await loadSentinelState();
});

function setupEventListeners() {
  refreshBtn.addEventListener("click", async () => {
    refreshBtn.classList.add("spinning");
    await loadSentinelState();
    setTimeout(() => refreshBtn.classList.remove("spinning"), 500);
  });

  scanHostBtn.addEventListener("click", handleHostScan);
  investigateBtn.addEventListener("click", handleInvestigateNext);
  openDashboardBtn.addEventListener("click", () => {
    chrome.tabs.create({ url: WEB_DASHBOARD_URL });
  });
}

/**
 * Loads current status and candidates from local Pasha 2.0 API.
 */
async function loadSentinelState() {
  setConnectionStatus("checking", "CONNECTING");

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 4000);

    // 1. Fetch Agent Status & Telemetry
    const statusRes = await fetch(`${API_BASE}/api/agent/status`, { signal: controller.signal });
    if (!statusRes.ok) throw new Error(`Agent status HTTP ${statusRes.status}`);
    const statusData = await statusRes.json();

    // 2. Fetch Candidate Summary
    const summaryRes = await fetch(`${API_BASE}/api/agent/candidates/summary`, { signal: controller.signal });
    if (!summaryRes.ok) throw new Error(`Summary HTTP ${summaryRes.status}`);
    const summaryData = await summaryRes.json();

    // 3. Fetch Top Candidates
    const candsRes = await fetch(`${API_BASE}/api/agent/candidates?limit=4`, { signal: controller.signal });
    const candsData = candsRes.ok ? await candsRes.json() : { candidates: [] };

    clearTimeout(timeoutId);

    // Render UI State
    renderAgentStatus(statusData);
    renderSummary(summaryData);
    renderCandidates(candsData.candidates || []);

    setConnectionStatus("online", "ONLINE");
    offlineBanner.classList.add("hidden");
    lastUpdatedEl.textContent = `Synced ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;

    // Sync state with background worker
    chrome.runtime.sendMessage({ action: "TRIGGER_POLL" }).catch(() => {});
  } catch (err) {
    console.warn("[Pasha Sentinel] Backend error:", err);
    setConnectionStatus("offline", "OFFLINE");
    offlineBanner.classList.remove("hidden");
    machineIdEl.textContent = "Offline";
    snapshotCountEl.textContent = "--";
    threatQueueCountEl.textContent = "--";
    threatBadgeEl.textContent = "!";
    candidatesListEl.innerHTML = `
      <div class="empty-state">
        <span>Engine offline. Ensure Pasha backend is running at ${API_BASE}.</span>
      </div>
    `;
  }
}

function setConnectionStatus(type, label) {
  connectionStatus.className = `status-pill status-${type}`;
  statusText.textContent = label;
}

function renderAgentStatus(data) {
  machineIdEl.textContent = data.machine_id || "LOCAL_HOST";
  snapshotCountEl.textContent = data.storage?.total_snapshots || 0;
  hostPostureEl.textContent = "ACTIVE DEFENSE";
}

function renderSummary(data) {
  const pending = data.counts_by_status?.PENDING || 0;
  const queued = data.counts_by_status?.QUEUED || 0;
  const activeCount = pending + queued;

  threatQueueCountEl.textContent = activeCount;
  threatBadgeEl.textContent = activeCount;

  if (activeCount > 0) {
    threatQueueCountEl.className = "item-value highlight-pink";
  } else {
    threatQueueCountEl.className = "item-value highlight-cyan";
  }
}

function renderCandidates(candidates) {
  if (!candidates || candidates.length === 0) {
    candidatesListEl.innerHTML = `
      <div class="empty-state">
        <span style="color: #10b981;">✓ Host clean. No suspicious candidates active.</span>
      </div>
    `;
    return;
  }

  candidatesListEl.innerHTML = "";

  candidates.forEach((c) => {
    const card = document.createElement("div");
    card.className = "candidate-card";

    const name = c.process_name || c.file_path?.split(/[\\/]/).pop() || c.target_entity || "Unknown";
    const category = (c.category || "GENERAL").replace("_", " ");
    const priority = Math.round(c.priority_score || 0);

    card.innerHTML = `
      <div class="candidate-head">
        <span class="candidate-name" title="${name}">${escapeHtml(name)}</span>
        <span class="candidate-score">SCORE: ${priority}</span>
      </div>
      <div class="candidate-meta">
        <span class="candidate-category">${escapeHtml(category)}</span>
        <span>Status: <strong>${escapeHtml(c.status || "QUEUED")}</strong></span>
      </div>
      <div class="candidate-actions">
        <button class="btn-mini btn-investigate" data-id="${c.candidate_id}">Investigate</button>
        <button class="btn-mini btn-view-console" data-id="${c.candidate_id}">Console</button>
      </div>
    `;

    // Attach button listeners safely
    const invBtn = card.querySelector(".btn-investigate");
    invBtn.addEventListener("click", async () => {
      invBtn.disabled = true;
      invBtn.textContent = "Analyzing...";
      try {
        const res = await fetch(`${API_BASE}/api/agent/investigate/${c.candidate_id}`, { method: "POST" });
        if (res.ok) {
          showToast(`Candidate ${name} investigated!`);
          await loadSentinelState();
        } else {
          showToast("Investigation failed.");
        }
      } catch (e) {
        showToast("Investigation error.");
      }
    });

    const viewBtn = card.querySelector(".btn-view-console");
    viewBtn.addEventListener("click", () => {
      chrome.tabs.create({ url: `${WEB_DASHBOARD_URL}?candidate=${c.candidate_id}` });
    });

    candidatesListEl.appendChild(card);
  });
}

/**
 * Triggers a fresh host scan and subsequent candidate detection.
 */
async function handleHostScan() {
  scanHostBtn.disabled = true;
  scanSpinner.classList.remove("hidden");
  showToast("Executing Windows security scan...");

  try {
    // 1. Trigger scan
    const scanRes = await fetch(`${API_BASE}/api/agent/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ save_to_store: true }),
    });

    if (!scanRes.ok) throw new Error(`Scan failed with HTTP ${scanRes.status}`);

    // 2. Trigger auto candidate detection
    await fetch(`${API_BASE}/api/agent/candidates/detect`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ auto_queue: true }),
    });

    showToast("Host scan complete. Snapshot recorded!");
    await loadSentinelState();
  } catch (err) {
    console.error(err);
    showToast("Scan failed. Engine offline?");
  } finally {
    scanHostBtn.disabled = false;
    scanSpinner.classList.add("hidden");
  }
}

/**
 * Investigates the next queued threat candidate.
 */
async function handleInvestigateNext() {
  investigateBtn.disabled = true;
  invSpinner.classList.remove("hidden");
  showToast("Triggering autonomous sandbox investigation...");

  try {
    const res = await fetch(`${API_BASE}/api/agent/investigate/next`, {
      method: "POST",
    });

    if (res.status === 404) {
      showToast("No pending threats in investigation queue.");
    } else if (!res.ok) {
      showToast(`Investigation error HTTP ${res.status}`);
    } else {
      const data = await res.json();
      showToast(`Investigated ${data.candidate_id || "threat"} successfully!`);
      await loadSentinelState();
    }
  } catch (err) {
    console.error(err);
    showToast("Investigation failed.");
  } finally {
    investigateBtn.disabled = false;
    invSpinner.classList.add("hidden");
  }
}

function showToast(msg) {
  toastEl.textContent = msg;
  toastEl.classList.remove("hidden");
  setTimeout(() => {
    toastEl.classList.add("hidden");
  }, 3200);
}

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
