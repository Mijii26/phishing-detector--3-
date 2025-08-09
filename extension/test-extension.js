// Test script to manually trigger email analysis in Gmail console
// Copy and paste this into Gmail's console (F12) to test

console.log("🧪 Testing Phishing Email Detector Extension")

// Declare EmailDetector variable
const EmailDetector = window.EmailDetector || {}

// Test 1: Check if extension is loaded
if (typeof EmailDetector !== "undefined") {
  console.log("✅ EmailDetector class is available")
} else {
  console.log("❌ EmailDetector class not found")
}

// Test 2: Manual email analysis test
async function testEmailAnalysis() {
  console.log("🔍 Testing email analysis...")

  const testEmail = {
    sender: "test@suspicious-domain.tk",
    subject: "URGENT: Verify your account now!",
    content:
      "Dear customer, your account will be suspended unless you verify immediately. Click here: http://fake-bank.tk/verify",
  }

  try {
    const response = await fetch("http://localhost:5000/api/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(testEmail),
    })

    if (response.ok) {
      const result = await response.json()
      console.log("✅ API Test Result:", result)
      console.log(`📊 Score: ${result.score}% | Verdict: ${result.verdict}`)
    } else {
      console.log("❌ API test failed:", response.status)
    }
  } catch (error) {
    console.log("❌ API connection failed:", error.message)
    console.log("💡 Make sure Python backend is running: python app.py")
  }
}

// Test 3: Check for email elements in current Gmail view
function checkEmailElements() {
  console.log("🔍 Checking for email elements in current view...")

  const selectors = ["[data-message-id]", ".ii.gt", '[role="listitem"] [data-thread-id]']

  let totalFound = 0
  selectors.forEach((selector) => {
    const elements = document.querySelectorAll(selector)
    console.log(`📧 Found ${elements.length} elements with selector: ${selector}`)
    totalFound += elements.length
  })

  console.log(`📊 Total email elements found: ${totalFound}`)

  if (totalFound === 0) {
    console.log("💡 Try opening an email or refreshing Gmail")
  }
}

// Test 4: Force process emails
function forceProcessEmails() {
  console.log("🔄 Forcing email processing...")

  // Try to create a new detector instance
  try {
    const detector = new EmailDetector()
    console.log("✅ New EmailDetector instance created")
  } catch (error) {
    console.log("❌ Failed to create EmailDetector:", error)
  }
}

// Run tests
console.log("Running extension tests...")
testEmailAnalysis()
checkEmailElements()

console.log("\n🧪 Manual Test Commands:")
console.log("- testEmailAnalysis() - Test API connection")
console.log("- checkEmailElements() - Check for email elements")
console.log("- forceProcessEmails() - Force email processing")
