/**
 * Pasha Security Sentinel - Background Service Worker (Manifest V3)
 * Provides background polling, badge alerts for prioritized security candidates,
 * and state synchronization with the local Pasha 2.0 API engine.
 */

const API_BASE = "http://127.0.0.1:8000";
const ALARM_NAME = "pasha_telemetry_poll";

// Register periodic health/candidate polling alarm on installation or startup
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[Pasha Sentinel] Extension installed. Initializing polling alarm...");
  await chrome.alarms.create(ALARM_NAME, {
    delayInMinutes: 0.1,
    periodInMinutes: 1.0,
  });
  await pollPashaStatus();
});

chrome.runtime.onStartup.addListener(async () => {
  console.log("[Pasha Sentinel] Browser started. Running immediate check...");
  await pollPashaStatus();
});

// Alarm trigger
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === ALARM_NAME) {
    await pollPashaStatus();
  }
});

// Message listener for popup triggers
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "TRIGGER_POLL") {
    pollPashaStatus()
      .then((res) => sendResponse({ success: true, data: res }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // Keep channel open for async response
  }
});

/**
 * Polls the local Pasha 2.0 engine to evaluate threat candidates and host posture.
 */
async function pollPashaStatus() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(`${API_BASE}/api/agent/candidates/summary`, {
      signal: controller.signal,
      headers: { "Content-Type": "application/json" },
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }

    const summary = await res.json();
    const pendingCount = summary.counts_by_status?.PENDING || 0;
    const queuedCount = summary.counts_by_status?.QUEUED || 0;
    const totalActiveThreats = pendingCount + queuedCount;

    // Update Extension Badge
    if (totalActiveThreats > 0) {
      await chrome.action.setBadgeText({ text: String(totalActiveThreats) });
      await chrome.action.setBadgeBackgroundColor({ color: "#ff0055" }); // Threat red
    } else {
      await chrome.action.setBadgeText({ text: "" }); // Clean
    }

    // Persist status in chrome.storage.local
    const state = {
      online: true,
      lastCheck: Date.now(),
      pendingCount,
      queuedCount,
      totalActiveThreats,
      totalCandidates: summary.total_candidates || 0,
      summary,
    };
    await chrome.storage.local.set({ pasha_state: state });
    return state;
  } catch (err) {
    console.warn("[Pasha Sentinel] Engine offline or unreachable:", err.message);
    await chrome.action.setBadgeText({ text: "OFF" });
    await chrome.action.setBadgeBackgroundColor({ color: "#475569" }); // Slate offline

    const offlineState = {
      online: false,
      lastCheck: Date.now(),
      error: err.message,
    };
    await chrome.storage.local.set({ pasha_state: offlineState });
    return offlineState;
  }
}
