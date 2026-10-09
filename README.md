<div align="center">

<img src="https://img.shields.io/badge/UPI-SHIELD-0B1220?style=for-the-badge&labelColor=FF9933&color=138808" alt="UPI Shield" />

# 🛡️ UPI Shield

### Pause. Inspect. Pay with confidence.

**A practical scam-screening prototype for suspicious messages, links, and UPI payment details.**

<p>
  <img src="https://img.shields.io/badge/Status-Prototype-7C3AED?style=flat-square" alt="Prototype status" />
  <img src="https://img.shields.io/badge/Python-FastAPI-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Frontend-HTML%20%7C%20CSS%20%7C%20JavaScript-F59E0B?style=flat-square" alt="Frontend" />
  <img src="https://img.shields.io/badge/Focus-Digital%20Safety-2563EB?style=flat-square" alt="Digital safety" />
</p>

*One interface. Three checks. A clearer moment to think before you act.*

</div>

---

## ✦ The idea

Digital scams often rely on urgency, impersonation, suspicious links, or payment requests that are difficult to assess at a glance. **UPI Shield** is a small, explainable first-check tool designed to help users examine suspicious content before taking action.

Instead of switching between separate tools, users can submit:

| Scanner | What it checks |
|---|---|
| 💬 **Message Scanner** | Text for configured scam indicators such as urgency, threats, OTP requests, or suspicious instructions |
| 🔗 **Link Scanner** | A submitted URL for indicators covered by the implemented detection rules |
| 💸 **UPI Scanner** | A submitted UPI payment URI/payload for suspicious or unexpected details |

> **Safety first:** UPI Shield is a screening aid, not a bank, payment processor, or guarantee of safety. A low-risk result does not prove that a message, website, or payment request is legitimate.

## ◈ Design direction

The interface is intended to feel like a **spatial glass dashboard**: layered surfaces, subtle depth, clear hierarchy, and restrained Indian tricolour accents.

- **Midnight glass** — dark navy surfaces for focus and contrast.
- **Saffron, white, and green** — small accents inspired by the Indian tricolour, rather than overwhelming the interface.
- **Explainable signals** — results should help users understand *why* an input may deserve attention.
- **Responsive layout** — scanners should share the same content width and visual rhythm as the dashboard.

## ✨ Features

- **Three focused scanners** in one interface.
- **Rule-based analysis** that is easy to inspect and improve.
- **Dashboard view** for a quick overview of the prototype's available stats.
- **FastAPI backend** with interactive API documentation.
- **Demo-friendly test inputs** for demonstrating both legitimate-looking and suspicious patterns.
- **Practical safety messaging** that encourages independent verification.

> Feature availability depends on the current implementation. The prototype does not automatically read SMS or WhatsApp messages, independently verify bank accounts, visit every submitted URL, or block payments.

## 🧭 How it works

```text
┌───────────────────────┐
│ User submits an input │
└───────────┬───────────┘
            │
     ┌──────┼──────┐
     ▼      ▼      ▼
  Message  Link    UPI
  Scanner  Scanner Scanner
     └──────┼──────┘
            ▼
┌──────────────────────────┐
│ Configured detection rules│
└───────────┬──────────────┘
            ▼
┌──────────────────────────┐
│ Result + warning signals │
└───────────┬──────────────┘
            ▼
┌──────────────────────────┐
│ Verify through official  │
│ channels before acting   │
└──────────────────────────┘
```

## 🧰 Tech stack

| Layer | Technology |
|---|---|
| Backend API | Python, FastAPI |
| Frontend | HTML, CSS, JavaScript |
| API testing | FastAPI / Swagger UI |
| Detection approach | Rule-based checks |
| Local development | Python virtual environment + Uvicorn |

## 🚀 Run locally

### 1. Requirements

- Python 3.10+ recommended
- pip
- A terminal such as PowerShell or the VS Code terminal

### 2. Open the project folder

```powershell
cd "C:\Users\lenovo\Downloads\upi-shield\upi"
```

Adjust the path if your project is stored elsewhere.

### 3. Create and activate a virtual environment

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, you can run the Python executable inside the environment directly, or use the VS Code terminal configured for your environment.

### 4. Install dependencies

If the project contains a `requirements.txt` file:

```powershell
python -m pip install -r requirements.txt
```

If it does not, install the packages your project imports (at minimum, the FastAPI/Uvicorn dependencies if those are used by `backend/main.py`):

```powershell
python -m pip install fastapi "uvicorn[standard]"
```

Install any additional project dependencies required by your code.

### 5. Start the backend

From the project root:

```powershell
python -m uvicorn backend.main:app --reload
```

If your entry point or package structure differs, use the import path that matches your project.

### 6. Open the app

- **Frontend:** http://127.0.0.1:8000/
- **API docs:** http://127.0.0.1:8000/docs

The frontend must be mounted or served by FastAPI for the first URL to work. If you serve it separately, open the URL for your frontend development server instead.

## 🧪 Try the API

Use the interactive docs at **`/docs`** to inspect the actual request fields and test endpoints exposed by your running backend. The project has been developed around routes such as:

- `POST /api/analyze/message`
- `POST /api/analyze/url`
- `POST /api/analyze/qr`
- `POST /api/verify/sender`
- `POST /api/payment/verify`
- `GET /api/test-cases`
- `GET /api/dashboard`

**Important:** Confirm these routes and their request schemas in `backend/main.py` or `/docs`; names and payloads may differ between versions. The payment verification flow, if present, is simulated unless explicitly connected to an authorized verification provider.

## 🎬 Demo inputs

Use synthetic examples only. The following are intended to exercise common rule patterns; actual results depend on the detector's implemented rules.

### Suspicious-pattern message

```text
URGENT: Your electricity connection will be disconnected in 10 minutes.
Install the attached APK immediately and share your OTP to avoid disconnection.
```

Possible indicators: urgency, threat of service disconnection, APK installation, OTP request.

### Benign-looking message

```text
Reminder: Your electricity bill is due on 15 October.
Please check the official provider app or website for your bill details.
```

A message can still be fraudulent even if it looks professional. Always verify using a trusted channel.

### Example URL

```text
https://example.com/
```

This is a reserved example domain, useful for testing basic URL handling. It is not evidence that a real website is safe.

### Synthetic UPI payload

```text
upi://pay?pa=demo@example.com&pn=TestMerchant&am=10&cu=INR
```

This is fabricated demonstration data. Do not send money to test payloads or treat the displayed payee name as verified identity.

## 🛡️ Responsible-use principles

1. **Never share an OTP, UPI PIN, password, or recovery code** with someone who contacts you unexpectedly.
2. Verify payment requests and urgent warnings through the institution's official app, website, or known phone number.
3. Do not assume that a low-risk result means an input is safe.
4. Avoid entering real personal, banking, or confidential information into a demo.
5. Treat false positives and false negatives as expected risks that must be measured and reduced.

## 🗺️ Roadmap

- [ ] Test against a documented set of benign and scam-pattern examples.
- [ ] Measure false-positive and false-negative rates.
- [ ] Improve result explanations and confidence calibration.
- [ ] Add safe, privacy-conscious logging and user feedback.
- [ ] Evaluate a labelled dataset before considering ML-based detection.
- [ ] Explore authorized integrations for stronger verification signals.
- [ ] Add accessibility checks and mobile-first usability testing.

## 🤝 Contributing

Ideas, bug reports, test cases, and usability feedback are welcome.

1. Fork the repository.
2. Create a branch for your change.
3. Make a focused update and test it locally.
4. Open a pull request describing the change and its limitations.

Please do not submit real credentials, personal banking information, or active malicious links as test fixtures.

## 📌 Current limitations

UPI Shield is a **prototype**, and its results depend on the rules and data implemented in the current code. It does not guarantee scam detection, replace a bank or payment app's protections, automatically monitor private messages, independently authenticate a payee, or prevent a transaction. A production version would require broader testing, careful privacy/security review, and appropriate integrations.

## 🇮🇳 Built around a simple principle

<div align="center">

### Pause before you pay.
### Inspect before you click.
### Verify before you trust.

**UPI Shield — awareness that starts with one check.**

<sub>Designed with subtle saffron • white • green accents</sub>

</div>
