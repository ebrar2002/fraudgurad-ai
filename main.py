from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import re
from urllib.parse import urlparse

app = FastAPI(title="FraudGuard AI")

class ScanRequest(BaseModel):
    text: str

def find_urls(text):
    return re.findall(r"https?://[^\s]+|www\.[^\s]+", text)

def analyze_text(input_text):
    text = input_text.lower()
    score = 0
    reasons = []

    patterns = {
        "Urgency pressure": ["urgent", "immediately", "right now", "act now"],
        "Money request": ["send money", "zelle", "cashapp", "wire transfer", "$"],
        "Gift card scam": ["gift card", "itunes card", "steam card"],
        "Phishing": ["verify your account", "password", "login", "bank account"],
        "Prize scam": ["winner", "prize", "congratulations"],
        "Crypto scam": ["crypto", "bitcoin", "investment"],
        "Romance scam": ["i love you", "dear", "stuck abroad"]
    }

    for category, words in patterns.items():
        for word in words:
            if word in text:
                score += 15
                reasons.append(f"{category}: '{word}' detected")

    urls = find_urls(input_text)

    for url in urls:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower()

        if "-" in domain:
            score += 10
            reasons.append("Suspicious URL: hyphen in domain")

        if any(word in domain for word in ["secure", "login", "verify", "update"]):
            score += 15
            reasons.append("Suspicious URL: phishing-style domain")

    score = min(score, 100)

    if score >= 70:
        risk = "High"
        recommendation = "🚨 Likely scam. Do NOT click links or send money."
    elif score >= 35:
        risk = "Medium"
        recommendation = "⚠️ Be careful. Verify before taking action."
    else:
        risk = "Low"
        recommendation = "✅ Looks safe but stay cautious."

    return {
        "risk_score": score,
        "risk_level": risk,
        "reasons": reasons,
        "urls_found": urls,
        "recommendation": recommendation
    }

@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>FraudGuard AI</title>

    <style>
        body {
            font-family: Arial;
            background: linear-gradient(135deg,#020617,#0f172a);
            color: white;
            padding: 40px;
        }

        .container {
            max-width: 800px;
            margin: auto;
            background: rgba(17,24,39,0.9);
            padding: 35px;
            border-radius: 20px;
            box-shadow: 0 0 40px rgba(56,189,248,0.2);
        }

        h1 {
            text-align: center;
            color: #38bdf8;
        }

        textarea {
            width: 100%;
            height: 160px;
            padding: 15px;
            border-radius: 12px;
            border: none;
            background: #020617;
            color: white;
            font-size: 15px;
        }

        button {
            margin-top: 15px;
            padding: 14px;
            width: 100%;
            border-radius: 12px;
            border: none;
            font-weight: bold;
            cursor: pointer;
        }

        .scan-btn {
            background: linear-gradient(90deg,#38bdf8,#22d3ee);
            color: #0f172a;
        }

        .example-btn {
            background: #1e293b;
            color: white;
        }

        .result {
            margin-top: 20px;
            padding: 20px;
            background: #020617;
            border-radius: 12px;
        }

        .High { color: red; }
        .Medium { color: orange; }
        .Low { color: green; }
    </style>
</head>

<body>

<div class="container">
    <h1>FraudGuard AI</h1>
    <p style="text-align:center;">Check messages before you trust them</p>

    <textarea id="textInput" placeholder="Paste suspicious message here..."></textarea>

    <button class="scan-btn" onclick="scanText()">Scan Now</button>
    <button class="example-btn" onclick="fillExample()">Try Example</button>

    <div id="result" class="result" style="display:none;"></div>
</div>

<script>

function fillExample(){
    document.getElementById("textInput").value =
    "Urgent! Your bank account is locked. Click http://secure-login-update.com now!";
}

async function scanText(){
    const text = document.getElementById("textInput").value;

    if(!text.trim()){
        alert("Paste something first");
        return;
    }

    document.getElementById("result").style.display = "block";
    document.getElementById("result").innerHTML = "⏳ Analyzing...";

    const response = await fetch("/scan", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify({text:text})
    });

    const data = await response.json();

    document.getElementById("result").innerHTML = `
        <h2 class="${data.risk_level}">Risk: ${data.risk_level}</h2>
        <p><b>Score:</b> ${data.risk_score}/100</p>
        <p><b>Recommendation:</b> ${data.recommendation}</p>
        <p><b>URLs:</b> ${data.urls_found.join(", ") || "None"}</p>

        <h3>Reasons:</h3>
        <ul>
            ${data.reasons.map(r=>`<li>${r}</li>`).join("")}
        </ul>

        <button onclick="copyResult()">Copy Result</button>
    `;
}

function copyResult(){
    const text = document.getElementById("result").innerText;
    navigator.clipboard.writeText(text);
    alert("Copied!");
}

</script>

</body>
</html>
"""

@app.post("/scan")
def scan_text(request: ScanRequest):
    return analyze_text(request.text)