// Enhanced content script for email detection with better Gmail/Outlook extraction
const SHOW_INLINE_BADGE = false

class EmailDetector {
  constructor() {
    this.isGmail = window.location.hostname.includes("mail.google.com")
    this.isOutlook = window.location.hostname.includes("outlook")
    this.processedEmails = new Set()
    this.processingEmails = new Set()
    this.chrome = window.chrome || window.browser
    this.apiUrl = "http://localhost:5000"
    this.isProcessing = false
    this.debugMode = true // Enable detailed debugging
    this.init()
    window.PhishNetDetector = this
  }

  debug(...args) {
    if (this.debugMode) {
      console.log("🛡️ PhishNet DEBUG:", ...args)
    }
  }

  init() {
    this.debug("Initialized on:", window.location.hostname)

    if (!this.isGmail && !this.isOutlook) {
      this.debug("❌ Unsupported email platform")
      return
    }

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => {
        this.startMonitoring()
      })
    } else {
      this.startMonitoring()
    }
  }

  startMonitoring() {
    this.debug("🔍 Starting email monitoring...")

    setTimeout(() => {
      this.processExistingEmails()
    }, 3000)

    this.startEmailMonitoring()
    this.monitorUrlChanges()

    this.chrome.runtime.onMessage.addListener((request) => {
      if (request.action === "showBanner" && request.result) {
        this.showTopBanner(request.result)
      }
    })
  }

  startEmailMonitoring() {
    let mutationTimeout = null

    const observer = new MutationObserver((mutations) => {
      if (mutationTimeout) {
        clearTimeout(mutationTimeout)
      }

      mutationTimeout = setTimeout(() => {
        if (this.isProcessing) {
          this.debug("⏳ Already processing, skipping...")
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
          this.debug("🔄 New email elements detected, processing...")
          this.processExistingEmails()
        }
      }, 800)
    })

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    })

    this.debug("👀 MutationObserver started")
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
        return !!document.querySelector(".ii.gt")
      }
      if (this.isOutlook) {
        return !!document.querySelector('[role="region"]') || !!document.querySelector(".ReadingPane")
      }
    } catch (_) {}
    return true
  }

  monitorUrlChanges() {
    let lastUrl = location.href
    let urlChangeTimeout = null

    new MutationObserver(() => {
      const url = location.href
      if (url !== lastUrl) {
        lastUrl = url
        this.debug("📧 URL changed, scheduling email check...")

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
      this.debug("⏳ Already processing emails, skipping...")
      return
    }

    this.isProcessing = true
    this.debug("🔍 Processing existing emails...")

    try {
      let emailElements = []

      if (this.isGmail) {
        this.debug("📧 Gmail: Looking for email elements...")

        const selectors = [
          "[data-message-id]:not(.phishing-processed)",
          ".ii.gt:not(.phishing-processed)",
          '[role="listitem"] [data-thread-id]:not(.phishing-processed)',
        ]

        selectors.forEach((selector) => {
          const elements = document.querySelectorAll(selector)
          this.debug(`   Found ${elements.length} elements with selector: ${selector}`)
          emailElements.push(...elements)
        })

        // Additional Gmail debugging
        this.debug("📧 Gmail DOM Analysis:")
        this.debug("   - Message containers:", document.querySelectorAll("[data-message-id]").length)
        this.debug("   - Email bodies:", document.querySelectorAll(".ii.gt").length)
        this.debug("   - Thread items:", document.querySelectorAll('[role="listitem"]').length)
        this.debug("   - Sender elements:", document.querySelectorAll("[email]").length)
        this.debug("   - Subject elements:", document.querySelectorAll("h2[data-thread-perm-id]").length)
      } else if (this.isOutlook) {
        emailElements = [
          ...document.querySelectorAll("[data-convid]:not(.phishing-processed)"),
          ...document.querySelectorAll(".rps_1aba:not(.phishing-processed)"),
          ...document.querySelectorAll('[role="region"]:not(.phishing-processed)'),
        ]
      }

      emailElements = [...new Set(emailElements)].filter((el) => !el.classList.contains("phishing-processed"))

      this.debug(`📧 Found ${emailElements.length} new email elements to process`)

      if (emailElements.length === 0) {
        this.isProcessing = false
        return
      }

      for (let i = 0; i < emailElements.length; i++) {
        const emailElement = emailElements[i]
        emailElement.classList.add("phishing-processed")

        setTimeout(() => {
          this.processEmail(emailElement)
        }, i * 350)
      }

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
      this.debug("🔍 Processing email element:", emailElement)

      const emailData = this.extractEmailData(emailElement)

      this.debug("📧 Extracted email data:", {
        sender: emailData.sender,
        subject: emailData.subject?.substring(0, 50) + "...",
        contentLength: emailData.content?.length || 0,
        hasValidData: !!(emailData.sender && emailData.content && emailData.content.length > 10),
      })

      if (!emailData || !emailData.content || emailData.content.length < 10) {
        this.debug("⚠️ Insufficient email data, skipping analysis")
        this.debug("   - Sender:", emailData?.sender || "missing")
        this.debug("   - Subject:", emailData?.subject || "missing")
        this.debug("   - Content length:", emailData?.content?.length || 0)
        return
      }

      const emailId = this.generateEmailId(emailData)

      if (this.processedEmails.has(emailId) || this.processingEmails.has(emailId)) {
        this.debug("⏭️ Email already processed, skipping")
        return
      }

      this.processingEmails.add(emailId)
      this.debug("🔍 Analyzing email from:", emailData.sender)

      this.addLoadingIndicator(emailElement)

      const isApiAvailable = await this.testApiConnection()
      if (!isApiAvailable) {
        this.debug("❌ API not available")
        this.removeLoadingIndicator(emailElement)
        this.showError(emailElement, "Backend not running")
        this.processingEmails.delete(emailId)
        return
      }

      try {
        this.debug("📤 Sending email data to API:", {
          sender: emailData.sender,
          subject: emailData.subject,
          contentPreview: emailData.content.substring(0, 100) + "...",
        })

        const result = await this.callAnalysisAPI(emailData)

        this.debug("📥 Received analysis result:", {
          score: result.score,
          verdict: result.verdict,
          hasDetails: !!result.details,
        })

        this.removeLoadingIndicator(emailElement)
        this.displayAnalysisResult(emailElement, result)
        this.processedEmails.add(emailId)

        this.debug(`✅ Analysis complete for ${emailData.sender}: ${result.verdict} (${result.score}%)`)

        if (this.isFullEmailOpen()) {
          this.showTopBanner(result)
        }
      } catch (error) {
        console.error("❌ Analysis failed:", error)
        this.debug("❌ Analysis API call failed:", error.message)
        this.removeLoadingIndicator(emailElement)
        this.showError(emailElement, "Analysis failed")
      }

      this.processingEmails.delete(emailId)
    } catch (error) {
      console.error("❌ Error processing email:", error)
      this.debug("❌ Email processing error:", error.message)
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
      const isOk = response.ok
      this.debug("🔗 API connection test:", isOk ? "✅ Success" : "❌ Failed")
      return isOk
    } catch (error) {
      this.debug("🔗 API connection test: ❌ Failed -", error.message)
      return false
    }
  }

  async callAnalysisAPI(emailData) {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 10000)

    try {
      this.debug("📤 Making API call to /api/analyze")

      const response = await fetch(`${this.apiUrl}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(emailData),
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      this.debug("📥 API response status:", response.status)

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const result = await response.json()
      this.debug("📥 API response data:", result)
      return result
    } catch (error) {
      clearTimeout(timeoutId)
      this.debug("❌ API call failed:", error.message)
      throw error
    }
  }

  extractEmailData(emailElement) {
    let sender = ""
    let subject = ""
    let content = ""

    try {
      if (this.isGmail) {
        this.debug("📧 Gmail: Starting email data extraction...")

        // Enhanced Gmail extraction with multiple fallbacks
        const senderElement =
          emailElement.querySelector("[email]") ||
          emailElement.closest("[data-message-id]")?.querySelector("[email]") ||
          document.querySelector(".gD[email]") ||
          document.querySelector(".go span[email]") ||
          document.querySelector(".qu [email]") ||
          document.querySelector(".yW span[email]")

        this.debug("📧 Gmail: Sender element found:", !!senderElement)
        if (senderElement) {
          this.debug("   - Element tag:", senderElement.tagName)
          this.debug("   - Email attribute:", senderElement.getAttribute("email"))
          this.debug("   - Text content:", senderElement.textContent)
        }

        const subjectElement =
          document.querySelector("h2[data-thread-perm-id]") ||
          document.querySelector(".hP") ||
          document.querySelector(".bog") ||
          document.querySelector("span[data-thread-perm-id]") ||
          document.querySelector(".qu .hP") ||
          document.querySelector("[data-thread-perm-id] span")

        this.debug("📧 Gmail: Subject element found:", !!subjectElement)
        if (subjectElement) {
          this.debug("   - Element tag:", subjectElement.tagName)
          this.debug("   - Text content:", subjectElement.textContent?.substring(0, 50))
          this.debug("   - Title attribute:", subjectElement.getAttribute("title"))
        }

        sender =
          senderElement?.getAttribute("email") || senderElement?.textContent?.match(/[\w.-]+@[\w.-]+\.\w+/)?.[0] || ""

        subject = subjectElement?.textContent?.trim() || subjectElement?.getAttribute("title") || ""

        // Enhanced content extraction for Gmail
        const contentElement =
          emailElement.querySelector(".ii.gt div") ||
          emailElement.querySelector(".ii.gt") ||
          document.querySelector(".ii.gt") ||
          document.querySelector(".a3s.aiL") ||
          document.querySelector(".ii.gt .a3s") ||
          emailElement

        this.debug("📧 Gmail: Content element found:", !!contentElement)
        if (contentElement) {
          this.debug("   - Element tag:", contentElement.tagName)
          this.debug("   - Class list:", contentElement.className)
          this.debug("   - Content length:", contentElement.textContent?.length || 0)
        }

        content = contentElement?.textContent?.trim() || ""

        this.debug("📧 Gmail: Final extraction results:")
        this.debug("   - Sender:", sender || "MISSING")
        this.debug("   - Subject:", subject?.substring(0, 50) || "MISSING")
        this.debug("   - Content length:", content.length)

        // If we're missing critical data, try alternative extraction methods
        if (!sender || !content) {
          this.debug("📧 Gmail: Trying alternative extraction methods...")

          // Try to get sender from different locations
          if (!sender) {
            const altSenderElements = [
              document.querySelector(".gD[email]"),
              document.querySelector(".go span[email]"),
              document.querySelector(".qu [email]"),
              document.querySelector('[data-hovercard-id*="@"]'),
            ]

            for (const el of altSenderElements) {
              if (el) {
                sender = el.getAttribute("email") || el.textContent?.match(/[\w.-]+@[\w.-]+\.\w+/)?.[0] || ""
                if (sender) {
                  this.debug("   - Found sender via alternative method:", sender)
                  break
                }
              }
            }
          }

          // Try to get content from different locations
          if (!content || content.length < 20) {
            const altContentElements = [
              document.querySelector(".a3s.aiL"),
              document.querySelector(".ii.gt .a3s"),
              document.querySelector("[data-message-id] .a3s"),
              document.querySelector(".adn.ads .a3s"),
            ]

            for (const el of altContentElements) {
              if (el && el.textContent && el.textContent.length > content.length) {
                content = el.textContent.trim()
                this.debug("   - Found content via alternative method, length:", content.length)
                break
              }
            }
          }
        }
      } else if (this.isOutlook) {
        // Outlook extraction (already working)
        const senderElement =
          emailElement.querySelector('[title*="@"]') ||
          emailElement.querySelector(".lpc_1aba") ||
          document.querySelector('[data-testid="message-header-from"]') ||
          document.querySelector('[aria-label*="From"]') ||
          document.querySelector('.allowTextSelection[title*="@"]')

        const subjectElement =
          document.querySelector('[aria-label*="Subject"]') ||
          document.querySelector(".rps_1aba") ||
          document.querySelector('[data-testid="message-subject"]') ||
          document.querySelector('div[role="heading"]') ||
          document.querySelector('.allowTextSelection[title]:not([title*="@"])')

        if (senderElement) {
          const titleAttr = senderElement.getAttribute("title")
          const textContent = senderElement.textContent

          sender =
            titleAttr?.match(/[\w.-]+@[\w.-]+\.\w+/)?.[0] || textContent?.match(/[\w.-]+@[\w.-]+\.\w+/)?.[0] || ""
        }

        if (subjectElement) {
          subject = subjectElement.textContent?.trim() || subjectElement.getAttribute("title") || ""
        }

        const contentElement =
          document.querySelector('[data-testid="message-body"]') ||
          document.querySelector(".rps_1aba") ||
          document.querySelector('[role="region"]') ||
          emailElement

        content = contentElement?.textContent?.trim() || ""

        this.debug("📧 Outlook extraction:", {
          sender,
          subject: subject.substring(0, 50),
          contentLength: content.length,
        })
      }

      // Clean and validate data
      sender = this.cleanText(sender)
      subject = this.cleanText(subject)
      content = this.cleanText(content)

      // Final validation and debugging
      const isValid = sender && content.length > 20
      this.debug("📧 Final extraction result:")
      this.debug("   - Valid:", isValid)
      this.debug("   - Sender:", sender || "MISSING")
      this.debug("   - Subject:", subject?.substring(0, 30) + "..." || "MISSING")
      this.debug("   - Content length:", content.length)

      return { sender, subject, content }
    } catch (error) {
      console.error("❌ Error extracting email data:", error)
      this.debug("❌ Email extraction error:", error.message)
      return { sender: "", subject: "", content: "" }
    }
  }

  cleanText(text) {
    if (!text) return ""
    return text.trim().replace(/\s+/g, " ")
  }

  generateEmailId(emailData) {
    try {
      const data = (emailData.sender || "") + (emailData.subject || "") + (emailData.content || "").substring(0, 100)

      let hash = 0
      if (data.length === 0) {
        return Date.now().toString(36) + Math.random().toString(36).substr(2, 5)
      }

      for (let i = 0; i < data.length; i++) {
        const char = data.charCodeAt(i)
        hash = (hash << 5) - hash + char
        hash = hash & hash
      }

      const positiveHash = Math.abs(hash)
      return positiveHash.toString(36)
    } catch (error) {
      console.error("Error generating email ID:", error)
      return Date.now().toString(36) + Math.random().toString(36).substr(2, 5)
    }
  }

  addLoadingIndicator(emailElement) {
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
      return
    }

    this.removeLoadingIndicator(emailElement)

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
    const existing = document.getElementById("phishnet-top-banner")
    if (existing) existing.remove()

    const isSafe = result.verdict === "SAFE" && result.score >= 70
    const isWarn = !isSafe

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

    document.body.appendChild(banner)

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

// Add manual testing functions to window for debugging
window.PhishNetDebug = {
  testExtraction: () => {
    console.log("🧪 Testing Gmail extraction manually...")
    const detector = window.PhishNetDetector
    if (detector) {
      detector.processExistingEmails()
    } else {
      console.log("❌ PhishNet detector not found")
    }
  },

  inspectDOM: () => {
    console.log("🔍 Gmail DOM Inspection:")
    console.log("- Message containers:", document.querySelectorAll("[data-message-id]").length)
    console.log("- Email bodies:", document.querySelectorAll(".ii.gt").length)
    console.log("- Sender elements:", document.querySelectorAll("[email]").length)
    console.log("- Subject elements:", document.querySelectorAll("h2[data-thread-perm-id]").length)

    // Show actual elements
    const senders = document.querySelectorAll("[email]")
    console.log("📧 Found senders:")
    senders.forEach((el, i) => {
      console.log(`  ${i + 1}. ${el.getAttribute("email")} (${el.tagName})`)
    })

    const subjects = document.querySelectorAll("h2[data-thread-perm-id]")
    console.log("📝 Found subjects:")
    subjects.forEach((el, i) => {
      console.log(`  ${i + 1}. ${el.textContent?.substring(0, 50)}... (${el.tagName})`)
    })
  },

  testAPI: async () => {
    console.log("🧪 Testing API connection...")
    try {
      const response = await fetch("http://localhost:5000/api/stats")
      if (response.ok) {
        const data = await response.json()
        console.log("✅ API working:", data)
      } else {
        console.log("❌ API error:", response.status)
      }
    } catch (error) {
      console.log("❌ API connection failed:", error.message)
    }
  },
}

window.EmailDetector = EmailDetector

try {
  console.log("🚀 Initializing PhishNet with enhanced Gmail debugging...")

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
