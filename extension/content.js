// Enhanced content script for email detection with Unicode support + top banner
const SHOW_INLINE_BADGE = false

class EmailDetector {
  constructor() {
    this.isGmail = window.location.hostname.includes("mail.google.com")
    this.isOutlook = window.location.hostname.includes("outlook")
    this.processedEmails = new Set()
    this.processingEmails = new Set() // Prevent duplicate processing
    this.chrome = window.chrome || window.browser // Support both Chrome and Firefox
    this.apiUrl = "http://localhost:5000"
    this.isProcessing = false // Global processing flag
    this.init()
    // Expose instance for message handlers
    window.PhishNetDetector = this
  }

  init() {
    console.log("🛡️ PhishNet initialized on:", window.location.hostname)

    // Check if we're on a supported email platform
    if (!this.isGmail && !this.isOutlook) {
      console.log("❌ Unsupported email platform")
      return
    }

    // Wait for page to fully load
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => {
        this.startMonitoring()
      })
    } else {
      this.startMonitoring()
    }
  }

  startMonitoring() {
    console.log("🔍 Starting email monitoring...")

    // Process existing emails after a delay
    setTimeout(() => {
      this.processExistingEmails()
    }, 3000)

    // Start monitoring for new emails
    this.startEmailMonitoring()

    // Monitor for URL changes (Gmail SPA navigation)
    this.monitorUrlChanges()

    // Listen for background-triggered banner requests (optional)
    this.chrome.runtime.onMessage.addListener((request) => {
      if (request.action === "showBanner" && request.result) {
        this.showTopBanner(request.result)
      }
    })
  }

  startEmailMonitoring() {
    let mutationTimeout = null

    const observer = new MutationObserver((mutations) => {
      // Debounce mutations to prevent excessive processing
      if (mutationTimeout) {
        clearTimeout(mutationTimeout)
      }

      mutationTimeout = setTimeout(() => {
        if (this.isProcessing) {
          console.log("⏳ Already processing, skipping...")
          return
        }

        let shouldCheck = false
        mutations.forEach((mutation) => {
          if (mutation.type === "childList" && mutation.addedNodes.length > 0) {
            mutation.addedNodes.forEach((node) => {
              if (node.nodeType === Node.ELEMENT_NODE && this.isEmailElement(node)) {
                shouldCheck = true
              }
            })
          }
        })

        if (shouldCheck) {
          console.log("🔄 New email elements detected, processing...")
          this.processExistingEmails()
        }
      }, 800) // 0.8s debounce
    })

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    })

    console.log("👀 MutationObserver started")
  }

  isEmailElement(element) {
    const emailSelectors = [
      "[data-message-id]",
      ".ii.gt",
      '[role="listitem"]',
      ".rps_1aba",
      "[data-convid]",
      ".adn.ads",
      "[data-thread-id]",
    ]

    return emailSelectors.some(
      (selector) =>
        (element.matches && element.matches(selector)) || (element.querySelector && element.querySelector(selector)),
    )
  }

  isFullEmailOpen() {
    try {
      if (this.isGmail) {
        // Gmail opened email usually renders with .ii.gt in the read view
        return !!document.querySelector(".ii.gt")
      }
      if (this.isOutlook) {
        // Outlook read pane detection (heuristic)
        return !!document.querySelector('[role="region"]') || !!document.querySelector(".ReadingPane")
      }
    } catch (_) {}
    // Fallback: assume open
    return true
  }

  monitorUrlChanges() {
    let lastUrl = location.href
    let urlChangeTimeout = null

    new MutationObserver(() => {
      const url = location.href
      if (url !== lastUrl) {
        lastUrl = url
        console.log("📧 URL changed, scheduling email check...")

        // Debounce URL changes
        if (urlChangeTimeout) {
          clearTimeout(urlChangeTimeout)
        }

        urlChangeTimeout = setTimeout(() => {
          if (!this.isProcessing) {
            this.processExistingEmails()
          }
        }, 1200)
      }
    }).observe(document, { subtree: true, childList: true })
  }

  async processExistingEmails() {
    if (this.isProcessing) {
      console.log("⏳ Already processing emails, skipping...")
      return
    }

    this.isProcessing = true
    console.log("🔍 Processing existing emails...")

    try {
      let emailElements = []

      if (this.isGmail) {
        // More specific Gmail selectors to avoid duplicates
        const selectors = [
          "[data-message-id]:not(.phishing-processed)",
          ".ii.gt:not(.phishing-processed)",
          '[role="listitem"] [data-thread-id]:not(.phishing-processed)',
        ]

        selectors.forEach((selector) => {
          const elements = document.querySelectorAll(selector)
          emailElements.push(...elements)
        })
      } else if (this.isOutlook) {
        emailElements = [
          ...document.querySelectorAll("[data-convid]:not(.phishing-processed)"),
          ...document.querySelectorAll(".rps_1aba:not(.phishing-processed)"),
        ]
      }

      // Remove duplicates and filter out already processed
      emailElements = [...new Set(emailElements)].filter((el) => !el.classList.contains("phishing-processed"))

      console.log(`📧 Found ${emailElements.length} new email elements`)

      if (emailElements.length === 0) {
        this.isProcessing = false
        return
      }

      // Process emails with staggered timing
      for (let i = 0; i < emailElements.length; i++) {
        const emailElement = emailElements[i]

        // Mark as being processed to avoid duplicates
        emailElement.classList.add("phishing-processed")

        setTimeout(() => {
          this.processEmail(emailElement)
        }, i * 350) // staggered
      }

      // Reset processing flag after all emails are queued
      setTimeout(
        () => {
          this.isProcessing = false
        },
        emailElements.length * 350 + 1000,
      )
    } catch (error) {
      console.error("❌ Error in processExistingEmails:", error)
      this.isProcessing = false
    }
  }

  async processEmail(emailElement) {
    try {
      const emailData = this.extractEmailData(emailElement)

      if (!emailData || !emailData.content || emailData.content.length < 10) {
        console.log("⚠️ Insufficient email data, skipping")
        return
      }

      const emailId = this.generateEmailId(emailData)

      // Check if already processed or currently processing
      if (this.processedEmails.has(emailId) || this.processingEmails.has(emailId)) {
        return
      }

      this.processingEmails.add(emailId)
      console.log("🔍 Analyzing email from:", emailData.sender)

      // Add loading indicator
      this.addLoadingIndicator(emailElement)

      // Test API connection
      const isApiAvailable = await this.testApiConnection()
      if (!isApiAvailable) {
        this.removeLoadingIndicator(emailElement)
        this.showError(emailElement, "Backend not running")
        this.processingEmails.delete(emailId)
        return
      }

      // Analyze email
      try {
        const result = await this.callAnalysisAPI(emailData)
        this.removeLoadingIndicator(emailElement)
        this.displayAnalysisResult(emailElement, result)
        this.processedEmails.add(emailId)
        console.log(`✅ Analysis complete for ${emailData.sender}: ${result.verdict} (${result.score}%)`)

        // Show top-of-screen banner for opened/full email view
        if (this.isFullEmailOpen()) {
          this.showTopBanner(result)
        }
      } catch (error) {
        console.error("❌ Analysis failed:", error)
        this.removeLoadingIndicator(emailElement)
        this.showError(emailElement, "Analysis failed")
      }

      this.processingEmails.delete(emailId)
    } catch (error) {
      console.error("❌ Error processing email:", error)
      this.removeLoadingIndicator(emailElement)
      this.showError(emailElement, "Processing error")
    }
  }

  async testApiConnection() {
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 3000)

      const response = await fetch(`${this.apiUrl}/api/stats`, {
        method: "GET",
        signal: controller.signal,
      })

      clearTimeout(timeoutId)
      return response.ok
    } catch (error) {
      return false
    }
  }

  async callAnalysisAPI(emailData) {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 10000)

    try {
      const response = await fetch(`${this.apiUrl}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(emailData),
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      return await response.json()
    } catch (error) {
      clearTimeout(timeoutId)
      throw error
    }
  }

  extractEmailData(emailElement) {
    let sender = ""
    let subject = ""
    let content = ""

    try {
      if (this.isGmail) {
        // Gmail extraction with better targeting
        const senderElement =
          emailElement.querySelector("[email]") ||
          emailElement.closest("[data-message-id]")?.querySelector("[email]") ||
          document.querySelector(".gD[email]")

        const subjectElement = document.querySelector("h2[data-thread-perm-id]") || document.querySelector(".hP")

        sender = senderElement?.getAttribute("email") || ""
        subject = subjectElement?.textContent?.trim() || ""

        // Get content more precisely
        const contentElement =
          emailElement.querySelector(".ii.gt div") || emailElement.querySelector(".ii.gt") || emailElement

        content = contentElement?.textContent?.trim() || ""
      } else if (this.isOutlook) {
        // Outlook extraction
        const senderElement =
          emailElement.querySelector('[title*="@"]') ||
          emailElement.querySelector(".lpc_1aba") ||
          document.querySelector('[data-testid="message-header-from"]')

        const subjectElement =
          document.querySelector('[aria-label*="Subject"]') ||
          document.querySelector(".rps_1aba") ||
          document.querySelector('[data-testid="message-subject"]')

        sender = senderElement?.textContent?.match(/[\w.-]+@[\w.-]+\.\w+/)?.[0] || ""
        subject = subjectElement?.textContent?.trim() || ""
        content = emailElement.textContent?.trim() || ""
      }

      // Clean and validate data
      sender = this.cleanText(sender)
      subject = this.cleanText(subject)
      content = this.cleanText(content)

      // Only log if we have meaningful data
      if (sender && content.length > 20) {
        console.log("📧 Extracted email data:", {
          sender,
          subject: subject.substring(0, 30) + "...",
          contentLength: content.length,
        })
      }

      return { sender, subject, content }
    } catch (error) {
      console.error("Error extracting email data:", error)
      return { sender: "", subject: "", content: "" }
    }
  }

  cleanText(text) {
    if (!text) return ""
    return text.trim().replace(/\s+/g, " ")
  }

  generateEmailId(emailData) {
    try {
      // Create a simple hash without using btoa() to avoid Unicode issues
      const data = (emailData.sender || "") + (emailData.subject || "") + (emailData.content || "").substring(0, 100)

      // Simple hash function that works with Unicode
      let hash = 0
      if (data.length === 0) {
        return Date.now().toString(36) + Math.random().toString(36).substr(2, 5)
      }

      for (let i = 0; i < data.length; i++) {
        const char = data.charCodeAt(i)
        hash = (hash << 5) - hash + char
        hash = hash & hash // Convert to 32-bit integer
      }

      // Convert to positive number and then to base36 string
      const positiveHash = Math.abs(hash)
      return positiveHash.toString(36)
    } catch (error) {
      console.error("Error generating email ID:", error)
      // Fallback to timestamp + random
      return Date.now().toString(36) + Math.random().toString(36).substr(2, 5)
    }
  }

  addLoadingIndicator(emailElement) {
    // Don't add if already exists
    if (emailElement.querySelector(".phishing-detector-loading")) {
      return
    }

    const indicator = document.createElement("div")
    indicator.className = "phishing-detector-loading"
    indicator.innerHTML = `
      <div style="
        position: absolute;
        top: 5px;
        right: 5px;
        background: #f0f0f0;
        border: 1px solid #ddd;
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 12px;
        color: #666;
        z-index: 10000;
        font-family: Arial, sans-serif;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      ">
        🔍 Analyzing...
      </div>
    `

    emailElement.style.position = "relative"
    emailElement.appendChild(indicator)
  }

  removeLoadingIndicator(emailElement) {
    const indicators = emailElement.querySelectorAll(".phishing-detector-loading, .phishing-detector-error")
    indicators.forEach((indicator) => indicator.remove())
  }

  showError(emailElement, error) {
    this.removeLoadingIndicator(emailElement)

    const indicator = document.createElement("div")
    indicator.className = "phishing-detector-error"
    indicator.innerHTML = `
      <div style="
        position: absolute;
        top: 5px;
        right: 5px;
        background: #ffebee;
        color: #c62828;
        border: 1px solid #e57373;
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 12px;
        z-index: 10000;
        font-family: Arial, sans-serif;
        cursor: pointer;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
      " title="${this.escapeHtml(error)}">
        ⚠️ Error
      </div>
    `

    emailElement.style.position = "relative"
    emailElement.appendChild(indicator)

    setTimeout(() => {
      if (indicator.parentNode) {
        indicator.remove()
      }
    }, 5000)
  }

  displayAnalysisResult(emailElement, result) {
    if (!SHOW_INLINE_BADGE) {
      // Do not render the small badge at all
      return
    }

    this.removeLoadingIndicator(emailElement)

    // Don't add if already exists
    if (emailElement.querySelector(".phishing-detector-result")) {
      return
    }

    const indicator = document.createElement("div")
    indicator.className = "phishing-detector-result"

    let backgroundColor, textColor, icon, message

    if (result.score >= 70) {
      backgroundColor = "#d4edda"
      textColor = "#155724"
      icon = "✅"
      message = `${result.score}% Safe`
    } else if (result.score >= 50) {
      backgroundColor = "#fff3cd"
      textColor = "#856404"
      icon = "⚠️"
      message = `${result.score}% Suspicious`
    } else {
      backgroundColor = "#f8d7da"
      textColor = "#721c24"
      icon = "🚨"
      message = `${result.score}% Unsafe`
    }

    indicator.innerHTML = `
      <div style="
        position: absolute;
        top: 5px;
        right: 5px;
        background: ${backgroundColor};
        color: ${textColor};
        border: 1px solid ${textColor}33;
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 12px;
        font-weight: bold;
        z-index: 10000;
        cursor: pointer;
        font-family: Arial, sans-serif;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      " title="Click for details">
        ${icon} ${message}
      </div>
    `

    indicator.addEventListener("click", (e) => {
      e.stopPropagation()
      this.showDetailedResults(result)
    })

    emailElement.style.position = "relative"
    emailElement.appendChild(indicator)
  }

  showTopBanner(result) {
    // Remove any existing banner
    const existing = document.getElementById("phishnet-top-banner")
    if (existing) existing.remove()

    const isSafe = result.verdict === "SAFE" && result.score >= 70
    const isWarn = !isSafe // SUSPICIOUS or UNSAFE -> red banner

    const banner = document.createElement("div")
    banner.id = "phishnet-top-banner"
    banner.className = `phishnet-banner ${isWarn ? "phishnet-banner--warn" : "phishnet-banner--safe"}`
    banner.setAttribute("role", "alert")
    banner.setAttribute("aria-live", isWarn ? "assertive" : "polite")

    const badgeText = isSafe ? "SAFE" : result.verdict
    const emoji = isSafe ? "✅" : result.verdict === "SUSPICIOUS" ? "⚠️" : "🚨"

    banner.innerHTML = `
      <div class="phishnet-banner__text">
        <span class="phishnet-banner__badge">${badgeText}</span>
        <span>${emoji} Security Score: ${result.score}/100 ${
          isWarn ? "- Exercise caution with this email." : "- This email appears legitimate."
        }</span>
      </div>
      <div class="phishnet-banner__actions">
        ${isSafe ? `<button class="phishnet-banner__btn" id="phishnet-ok-btn" aria-label="OK">OK</button>` : ``}
        <button class="phishnet-banner__close" id="phishnet-close-btn" aria-label="Dismiss banner">×</button>
      </div>
    `

    // Insert into document
    document.body.appendChild(banner)

    // Dismiss logic
    let autoDismissTimer = null

    const remove = () => {
      if (autoDismissTimer) {
        clearTimeout(autoDismissTimer)
        autoDismissTimer = null
      }
      banner.remove()
    }

    banner.querySelector("#phishnet-close-btn").addEventListener("click", remove)
    const okBtn = banner.querySelector("#phishnet-ok-btn")
    if (okBtn) okBtn.addEventListener("click", remove)

    // Auto-dismiss SAFE banner after 5 seconds
    if (isSafe) {
      autoDismissTimer = setTimeout(remove, 5000)
    }
  }

  showDetailedResults(result) {
    const existingModal = document.querySelector(".phishing-detector-modal")
    if (existingModal) {
      existingModal.remove()
    }

    const modal = document.createElement("div")
    modal.className = "phishing-detector-modal"
    modal.innerHTML = `
      <div style="
        background: white;
        border-radius: 8px;
        padding: 20px;
        max-width: 500px;
        width: 90%;
        max-height: 80%;
        overflow-y: auto;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
      ">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
          <h3 style="margin: 0; color: #333;">PhishNet Security Analysis</h3>
          <button class="close-modal" style="
            background: none;
            border: none;
            font-size: 20px;
            cursor: pointer;
            color: #666;
            padding: 0;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
          ">×</button>
        </div>
        
        <div style="margin-bottom: 15px;">
          <strong>Verdict:</strong> ${result.verdict}<br>
          <strong>Security Score:</strong> ${result.score}/100
        </div>
        
        ${
          result.details && result.details.issues && result.details.issues.length > 0
            ? `
          <div style="margin-bottom: 15px;">
            <strong>Issues Found:</strong>
            <ul style="margin: 5px 0; padding-left: 20px;">
              ${result.details.issues.map((issue) => `<li>${this.escapeHtml(issue)}</li>`).join("")}
            </ul>
          </div>
        `
            : ""
        }
        
        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; text-align: center; font-size: 14px;">
          <div>
            <strong>Domain Score</strong><br>
            ${result.details?.domain_score || "N/A"}
          </div>
          <div>
            <strong>Content Score</strong><br>
            ${result.details?.content_score || "N/A"}
          </div>
          <div>
            <strong>URL Score</strong><br>
            ${result.details?.url_score || "N/A"}
          </div>
        </div>
      </div>
    `

    modal.querySelector(".close-modal").addEventListener("click", () => {
      modal.remove()
    })

    modal.addEventListener("click", (e) => {
      if (e.target === modal) {
        modal.remove()
      }
    })

    document.body.appendChild(modal)
  }

  escapeHtml(text) {
    const div = document.createElement("div")
    div.textContent = text
    return div.innerHTML
  }
}

// Make EmailDetector available globally for testing
window.EmailDetector = EmailDetector

// Initialize with better error handling
try {
  console.log("🚀 Initializing PhishNet...")

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      new EmailDetector()
    })
  } else {
    new EmailDetector()
  }
} catch (error) {
  console.error("❌ Failed to initialize Email Detector:", error)
}
