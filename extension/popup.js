// Popup script for Chrome extension
document.addEventListener("DOMContentLoaded", async () => {
  await loadPopupData()
  setupEventListeners()
})

async function loadPopupData() {
  try {
    // Load stats from storage
    const result = await window.chrome.storage.local.get([
      "emailsScanned",
      "threatsBlocked",
      "recentAnalysis",
      "protectionEnabled",
    ])

    document.getElementById("emails-scanned").textContent = result.emailsScanned || 0
    document.getElementById("threats-blocked").textContent = result.threatsBlocked || 0

    // Update protection status
    const protectionEnabled = result.protectionEnabled !== false // Default to true
    updateProtectionStatus(protectionEnabled)

    // Load recent analysis
    const recentAnalysis = result.recentAnalysis || []
    displayRecentAnalysis(recentAnalysis)
  } catch (error) {
    console.error("Error loading popup data:", error)
  }
}

function setupEventListeners() {
  // Toggle protection
  document.getElementById("toggle-protection").addEventListener("click", async () => {
    const result = await window.chrome.storage.local.get(["protectionEnabled"])
    const currentStatus = result.protectionEnabled !== false
    const newStatus = !currentStatus

    await window.chrome.storage.local.set({ protectionEnabled: newStatus })
    updateProtectionStatus(newStatus)

    // Send message to content scripts
    window.chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        window.chrome.tabs.sendMessage(tabs[0].id, {
          action: "toggleProtection",
          enabled: newStatus,
        })
      }
    })
  })

  // Clear data
  document.getElementById("clear-data").addEventListener("click", async () => {
    if (confirm("Are you sure you want to clear all data?")) {
      await window.chrome.storage.local.clear()
      await loadPopupData()
    }
  })
}

function updateProtectionStatus(enabled) {
  const statusDiv = document.getElementById("status")
  const statusText = document.getElementById("status-text")
  const toggleBtn = document.getElementById("toggle-protection")

  if (enabled) {
    statusDiv.className = "status"
    statusText.textContent = "🔍 Monitoring emails..."
    toggleBtn.innerHTML = "⏸️ Pause Protection"
  } else {
    statusDiv.className = "status warning"
    statusText.textContent = "⚠️ Protection paused"
    toggleBtn.innerHTML = "▶️ Resume Protection"
  }
}

function displayRecentAnalysis(recentAnalysis) {
  const recentList = document.getElementById("recent-list")

  if (!recentAnalysis || recentAnalysis.length === 0) {
    recentList.innerHTML = `
      <div style="text-align: center; color: #666; font-size: 12px; padding: 20px 0;">
        No recent analysis
      </div>
    `
    return
  }

  recentList.innerHTML = recentAnalysis
    .slice(0, 5)
    .map((analysis) => {
      let scoreClass = "score-safe"
      if (analysis.score < 50) scoreClass = "score-unsafe"
      else if (analysis.score < 70) scoreClass = "score-suspicious"

      return `
      <div class="analysis-item">
        <div>
          <div style="font-size: 12px; font-weight: bold; color: #333;">
            ${analysis.sender.length > 25 ? analysis.sender.substring(0, 25) + "..." : analysis.sender}
          </div>
          <div style="font-size: 11px; color: #666;">
            ${new Date(analysis.timestamp).toLocaleTimeString()}
          </div>
        </div>
        <div class="analysis-score ${scoreClass}">
          ${analysis.score}%
        </div>
      </div>
    `
    })
    .join("")
}

// Listen for messages from background script
window.chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "updateStats") {
    loadPopupData()
  }
})
