const API_BASE_URL = "http://localhost:5000";
const USE_SYSTEM_NOTIFICATIONS = false;

// Helper to promisify chrome.storage.local.get
function getStorage(keys) {
  return new Promise((resolve) => {
    chrome.storage.local.get(keys, (result) => resolve(result || {}));
  });
}

// Helper to promisify chrome.storage.local.set
function setStorage(obj) {
  return new Promise((resolve) => {
    chrome.storage.local.set(obj, () => resolve());
  });
}

// Listen for messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log("📨 Background received message:", request.action);

  if (request.action === "analyzeEmail") {
    analyzeEmail(request.emailData)
      .then((result) => {
        console.log("✅ Analysis successful:", result);
        sendResponse({ success: true, result });

        if (USE_SYSTEM_NOTIFICATIONS) {
          showNotification(result);
        }
        updateStats(result);
      })
      .catch((error) => {
        console.error("❌ Analysis error:", error);
        sendResponse({ success: false, error: error.message });
      });
    return true; // Keep channel open
  }
});

// Analyze email using the API
async function analyzeEmail(emailData) {
  try {
    console.log("🔍 Analyzing email from:", emailData.sender);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(emailData),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("❌ API request failed:", error);
    throw error;
  }
}

// Show notification (optional)
function showNotification(result) {
  if (!USE_SYSTEM_NOTIFICATIONS) return;

  try {
    const notificationOptions = {
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: "",
      message: "",
    };

    if (result.score >= 70) {
      notificationOptions.title = "✅ Email is Safe";
      notificationOptions.message = `Security Score: ${result.score}% - This email appears to be legitimate.`;
    } else if (result.score >= 50) {
      notificationOptions.title = "⚠️ Suspicious Email";
      notificationOptions.message = `Security Score: ${result.score}% - Exercise caution with this email.`;
    } else {
      notificationOptions.title = "🚨 Unsafe Email";
      notificationOptions.message = `Security Score: ${result.score}% - This email may be a phishing attempt!`;
    }

    chrome.notifications.create("emailAnalysis", notificationOptions);
  } catch (error) {
    console.error("❌ Failed to show notification:", error);
  }
}

// Update extension statistics
async function updateStats(result) {
  try {
    const storage = await getStorage(["emailsScanned", "threatsBlocked", "recentAnalysis"]);

    const emailsScanned = (storage.emailsScanned || 0) + 1;
    const threatsBlocked = storage.threatsBlocked || 0;
    const recentAnalysis = storage.recentAnalysis || [];

    recentAnalysis.unshift({
      sender: result.details?.sender_domain || "Unknown",
      score: result.score,
      timestamp: new Date().toISOString(),
    });

    if (recentAnalysis.length > 10) {
      recentAnalysis.splice(10);
    }

    await setStorage({
      emailsScanned,
      threatsBlocked: result.score < 70 ? threatsBlocked + 1 : threatsBlocked,
      recentAnalysis,
    });

    console.log("📊 Stats updated:", { emailsScanned, threatsBlocked });
  } catch (error) {
    console.error("❌ Failed to update stats:", error);
  }
}

// Handle notification clicks
chrome.notifications.onClicked.addListener((notificationId) => {
  if (notificationId === "emailAnalysis") {
    chrome.tabs.create({ url: `${API_BASE_URL}` });
  }
});

// Initialize extension
chrome.runtime.onInstalled.addListener(() => {
  console.log("🛡️ PhishNet extension installed");
  chrome.storage.local.set({
    protectionEnabled: true,
    emailsScanned: 0,
    threatsBlocked: 0,
    recentAnalysis: [],
  });
});

chrome.runtime.onStartup.addListener(() => {
  console.log("🚀 PhishNet extension started");
});

// Test API connection
async function testApiConnection() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${API_BASE_URL}/api/stats`, {
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      console.log("✅ API connection successful");
    } else {
      console.log("⚠️ API connection failed - make sure backend is running");
    }
  } catch {
    console.log("❌ API not available - make sure backend is running on port 5000");
  }
}

testApiConnection();
