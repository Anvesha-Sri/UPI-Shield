# UPI Shield — Organized Demo Dataset & Test Plan

**Purpose:** A balanced, repeatable demo dataset for the UPI Shield scam-detection prototype. It contains legitimate and illegitimate message examples, URL samples, and synthetic UPI payloads.

> **Safety note:** All message content is synthetic. Placeholder domains and UPI IDs are not real payment destinations. Do not send money, install APKs, follow suspicious links, or use real credentials during testing.

## Contents

1. Test procedure
2. Message Scanner dataset
3. Link Scanner dataset
4. UPI Checker dataset
5. Expected labels and evaluation worksheet
6. Presentation script
7. Troubleshooting

---

## 1. Test procedure

1. Start the FastAPI backend.
2. Open the frontend in a browser.
3. Run each sample through the matching scanner.
4. Record the **actual** risk score, decision, indicators, and any error.
5. Compare actual output with the intended label in this document.
6. Investigate false positives and false negatives; do not change recorded results just to match expectations.

Expected labels are for evaluating the demo dataset, not guaranteed results from the current rules engine.

## 2. Message Scanner dataset

### Legitimate samples

#### M01 — Electricity bill reminder
- **Label:** Legitimate-style
- **Sender:** Electricity Provider
- **Message:**

> Your electricity bill is due on 15 October. Please check your bill in the official electricity provider app.

- **Why included:** Routine reminder; no threat, password request, or unknown link.
- **Expected observation:** Should generally be lower risk, depending on detector rules.

#### M02 — Payment confirmation
- **Label:** Legitimate-style
- **Sender:** Demo Bank
- **Message:**

> Your demo transaction of Rs. 250 was successful. Reference: DEMO123456. For help, open your bank's official app.

- **Why included:** Ordinary transaction notification with a synthetic reference.
- **Expected observation:** Should generally be lower risk.

#### M03 — Friend's message
- **Label:** Legitimate-style
- **Sender:** Friend
- **Message:**

> Hi, I have sent you Rs. 300 for lunch. Please check your UPI app when you have time.

- **Why included:** Ordinary conversational wording.
- **Expected observation:** Should generally be lower risk.

#### M04 — College fee reminder
- **Label:** Legitimate-style
- **Sender:** College Office
- **Message:**

> This is a reminder that semester fees are due next week. Please check the student portal for the amount and payment deadline.

- **Why included:** Routine reminder directing the recipient to a portal.
- **Expected observation:** Should generally be lower risk.

### Illegitimate / scam-pattern samples

#### M05 — Fake electricity disconnection
- **Label:** Illegitimate / high-risk pattern
- **Sender:** Power-Support-Alert
- **Message:**

> URGENT! Your electricity will be disconnected in 10 minutes. Call 9876543210 immediately and install the billing support APK.

- **Indicators to look for:** Urgency, disconnection threat, phone number, APK installation.
- **Safe action:** Do not install the app or use the contact details in the message. Contact the provider independently.

#### M06 — OTP and PIN request
- **Label:** Illegitimate / critical-risk pattern
- **Sender:** Bank Security
- **Message:**

> Your bank account will be blocked today. Send your OTP and ATM PIN to verify your identity immediately.

- **Indicators to look for:** OTP/PIN request, urgency, account-block threat.
- **Safe action:** Never share OTPs, PINs, passwords, or recovery codes.

#### M07 — Fake KYC warning
- **Label:** Illegitimate / high-risk pattern
- **Sender:** KYC-VERIFY
- **Message:**

> Your KYC has expired. Your account will be suspended in 30 minutes. Open the verification page and enter your banking details.

- **Indicators to look for:** KYC theme, suspension threat, urgency, banking-detail request.
- **Safe action:** Verify through the official bank app or a known official channel.

#### M08 — Fake cashback offer
- **Label:** Illegitimate / high-risk pattern
- **Sender:** Rewards-Team
- **Message:**

> Congratulations! You won Rs. 5000 cashback. Pay a Rs. 99 processing fee immediately to claim your prize.

- **Indicators to look for:** Unexpected prize, advance fee, urgency.
- **Safe action:** Verify offers independently; do not pay an unexpected claim fee.

---

## 3. Link Scanner dataset

The `.example` top-level domain is reserved for documentation. These are illustrative strings, not real banking or payment sites. Treat them as scanner inputs; do not navigate to suspicious URLs.

| ID | Intended test label | URL | What to evaluate |
|---|---|---|---|
| L01 | Benign baseline | `https://example.com/` | Baseline URL handling |
| L02 | Benign documentation page | `https://www.iana.org/help/example-domains` | Ordinary HTTPS URL |
| L03 | Suspicious pattern | `http://secure-bank-verify.example/login` | Bank/verification wording and HTTP |
| L04 | Suspicious pattern | `http://electricity-disconnect.example/pay-now` | Threat-themed hostname/path |
| L05 | Suspicious pattern | `http://cashback-claim.example/reward` | Prize/cashback wording |
| L06 | Suspicious pattern | `http://kyc-update.example/verify-account` | KYC/account verification wording |

**Interpretation note:** The intended label is a test category, not proof of maliciousness. A URL's appearance alone cannot establish whether a real site is safe or fraudulent.

---

## 4. UPI Checker dataset

These payloads are synthetic parser inputs. `example.com`-style placeholder identifiers are not verified UPI recipients. Never initiate a payment using them.

### P01 — Basic payment payload
```text
upi://pay?pa=merchant%40example.com&pn=Demo%20Store&am=250.00&cu=INR&tn=Demo%20purchase
```
- **Test type:** Parseable example
- **Evaluate:** Whether payee label, amount, currency, and transaction note are extracted.

### P02 — Urgent refund-themed payload
```text
upi://pay?pa=unknown-collect%40example.com&pn=Urgent%20Refund&am=9999.00&cu=INR&tn=Verify%20account%20immediately
```
- **Test type:** Suspicious-themed example
- **Evaluate:** Whether the parser extracts the amount and note, and whether the detector explains any relevant indicators.
- **Caution:** The text alone does not prove fraud.

### P03 — Missing amount
```text
upi://pay?pa=merchant%40example.com&pn=Demo%20Merchant&cu=INR&tn=Test%20request
```
- **Test type:** Incomplete payload
- **Evaluate:** Whether the app handles a missing amount gracefully.

### P04 — Invalid payload
```text
this-is-not-a-upi-payment-payload
```
- **Test type:** Malformed input
- **Evaluate:** Whether the app returns a clear validation message instead of crashing.

---

## 5. Evaluation worksheet

Fill the actual results from your running app. Do not assume the expected outcome occurred.

| ID | Scanner | Intended label/test | Actual decision | Actual score | Indicators / notes |
|---|---|---|---|---|---|
| M01 | Message | Legitimate-style |  |  |  |
| M02 | Message | Legitimate-style |  |  |  |
| M03 | Message | Legitimate-style |  |  |  |
| M04 | Message | Legitimate-style |  |  |  |
| M05 | Message | Illegitimate pattern |  |  |  |
| M06 | Message | Illegitimate pattern |  |  |  |
| M07 | Message | Illegitimate pattern |  |  |  |
| M08 | Message | Illegitimate pattern |  |  |  |
| L01 | Link | Benign baseline |  |  |  |
| L02 | Link | Benign documentation URL |  |  |  |
| L03 | Link | Suspicious pattern |  |  |  |
| L04 | Link | Suspicious pattern |  |  |  |
| L05 | Link | Suspicious pattern |  |  |  |
| L06 | Link | Suspicious pattern |  |  |  |
| P01 | UPI | Parseable example |  |  |  |
| P02 | UPI | Suspicious-themed example |  |  |  |
| P03 | UPI | Missing amount |  |  |  |
| P04 | UPI | Malformed input |  |  |  |

### Basic evaluation terms

- **True positive:** A scam-pattern sample is correctly flagged.
- **True negative:** A legitimate-style sample is correctly treated as low risk.
- **False positive:** A legitimate-style sample is incorrectly flagged.
- **False negative:** A scam-pattern sample is incorrectly treated as low risk.

For formal accuracy/precision/recall calculations, use a clearly defined binary ground truth and the detector's actual decisions. Parser-invalid samples should be evaluated separately from fraud classification.

---

## 6. Suggested presentation script

1. **Explain the goal:** UPI Shield analyzes text, URLs, and UPI payloads for risk indicators before a user acts.
2. **Show a legitimate case:** Run M01 or M04 and review the actual score and explanation.
3. **Show the main scam scenario:** Run M05. Identify the urgency, disconnection threat, and APK request.
4. **Show a credential scam:** Run M06 and explain why OTPs and PINs must never be shared.
5. **Show URL analysis:** Test L01 and L03, comparing the explanations rather than relying on the label alone.
6. **Show UPI parsing:** Run P01 and P03 to demonstrate extraction and missing-field handling.
7. **Discuss limitations:** Explain that this is a prototype; it does not independently verify bank ownership or block a real transfer unless those features are actually integrated.

### Short narration you can say

> “UPI Shield is a prototype that uses rule-based analysis to identify suspicious patterns in messages, URLs, and UPI payment payloads. I test both legitimate-style and scam-pattern examples to observe false positives as well as missed scams. The system provides risk indicators and recommendations; it does not guarantee that a transaction or website is safe.”

---

## 7. Troubleshooting the demo

- **`404 Not Found`:** Check the route path in `backend/main.py` and compare it with `/docs`.
- **`422 Unprocessable Entity`:** Check the exact request body expected by the endpoint in `/docs`.
- **`500 Internal Server Error`:** Inspect the Uvicorn terminal for the traceback.
- **`Failed to fetch`:** Confirm Uvicorn is running and the frontend calls the correct backend URL.
- **Scanner opens but no result appears:** Check browser DevTools → Console and Network.
- **Sample label differs from actual result:** Record it honestly. Review the rules in `detector.py`; do not report the expected label as if it were the actual detector output.

## Safety checklist

- [ ] Use synthetic test inputs only.
- [ ] Do not enter real OTPs, PINs, passwords, or customer details.
- [ ] Do not install APKs or open suspicious links.
- [ ] Do not send payments to placeholder UPI IDs.
- [ ] Record actual outputs and errors.
- [ ] State the prototype's limitations in the report.
