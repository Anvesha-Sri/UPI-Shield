"""UPI Shield detection engine. Static analysis only: nothing is ever visited, paid or sent."""
import re, math, difflib, json
from urllib.parse import urlparse, parse_qs, unquote

TRUSTED_SENDERS = {"ELECTRICITY-TEST": {"org": "Electricity Board", "domain": "electricity.example.test"},
                   "BANK-DEMO": {"org": "Demo Bank", "domain": "bank-demo.test"}}
TRUSTED_DOMAINS = {v["domain"] for v in TRUSTED_SENDERS.values()}
TRUSTED_VPAS = {"electricity@demo": "Electricity Board", "demobank@demo": "Demo Bank"}
KNOWN_CONTACTS = {"ravi.kumar@demo", "milkman@demo"}
ORG_WORDS = ["electricity", "bank", "kyc", "rbi", "police", "customs", "income tax", "telecom", "courier"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy"}
AVG_AMOUNT = 800  # simulated user history
URL_RE = re.compile(r"https?://[^\s]+", re.I)
PHONE_RE = re.compile(r"(?:\+91[\s-]?)?\b[6-9]\d{4}[\s-]?\d{5}\b")
VPA_RE = re.compile(r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b")
AMT_RE = re.compile(r"(?:₹|rs\.?|inr)\s?([\d,]+(?:\.\d+)?)", re.I)

MSG_RULES = [  # name, severity, points, regex, explanation
 ("Artificial urgency", "high", 15, r"urgent|immediately|right now|within \d+ ?(min|hour)|today|last warning|act now|\bnow\b", "The message pressures you to act before you can verify."),
 ("Threat of suspension/penalty", "high", 20, r"disconnect|blocked|suspend|deactivat|freez|frozen|legal action|arrest|penalty", "Threats of losing service or money are a classic fear trigger."),
 ("Request for OTP/PIN", "critical", 30, r"(share|send|enter|reply|tell|provide)\s+(your\s+)?(upi\s+)?(otp|pin|cvv|password)", "No genuine organisation asks you to share an OTP or PIN."),
 ("Payment approval request", "high", 15, r"approve|collect request|pay (now|immediately)|using the link|pay ₹|pay rs|accept the request", "You are asked to approve or send money. Approving a collect request SENDS money."),
 ("APK / app install request", "critical", 30, r"\.apk|install (our|the|this) .{0,20}app|download (our|the|this) .{0,20}app", "Side-loaded apps can read SMS/OTPs and take over payments."),
 ("Advance fee / deposit demand", "high", 20, r"registration fee|refundable|processing fee|joining fee|security deposit", "Legitimate jobs and refunds never require you to pay first."),
 ("Job / prize lure", "medium", 10, r"work[- ]from[- ]home|job offer|selected for|lottery|you have won|cashback reward", "Too-good-to-be-true offers are used to start the scam."),
]

def level(s): return next(n for t, n in [(10, "SAFE"), (30, "LOW"), (55, "MEDIUM"), (80, "HIGH"), (101, "CRITICAL")] if s < t)
def decision(s): return "ALLOW" if s < 30 else "WARN" if s < 55 else "BLOCK"
def combine(inds, factor=1.0):
    """Diminishing-returns normalisation: never exceeds 100, extra rules add less."""
    return min(100, round(100 * (1 - math.exp(-sum(i["score"] for i in inds) * factor / 45))))
def ind(name, sev, score, expl): return {"name": name, "severity": sev, "score": score, "explanation": expl}

def verify_sender(sender, text=""):
    s = (sender or "").strip()
    if s.lower().startswith("contact:"):
        return {"sender": s, "status": "VERIFIED", "detail": "Saved contact in your address book."}
    if s.upper() in TRUSTED_SENDERS:
        o = TRUSTED_SENDERS[s.upper()]
        return {"sender": s, "status": "VERIFIED", "detail": f"Matches official sender for {o['org']} (official domain {o['domain']})."}
    claims = any(w in (text or "").lower() for w in ORG_WORDS)
    near = difflib.get_close_matches(s.upper(), TRUSTED_SENDERS.keys(), n=1, cutoff=0.5)
    if near and s:
        return {"sender": s, "status": "MISMATCH", "claims_org": True, "detail": f"Sender '{s}' resembles official '{near[0]}' but does not match it. Possible impersonation."}
    if claims:
        return {"sender": s or "(unknown)", "status": "MISMATCH", "claims_org": True, "detail": "Message claims to represent an organisation but the sender cannot be verified against official sender IDs."}
    return {"sender": s or "(unknown)", "status": "UNVERIFIED", "claims_org": False, "detail": "Sender not found in the trusted dataset."}

def analyze_url(url):
    inds, u = [], urlparse(url.strip())
    host = (u.hostname or "").lower()
    if not host: return {"url": url, "risk_score": 50, "risk_level": "MEDIUM", "decision": "WARN", "indicators": [ind("Malformed URL", "medium", 25, "Could not parse a host name.")], "trusted": False}
    if host in TRUSTED_DOMAINS and u.scheme == "https":
        return {"url": url, "risk_score": 0, "risk_level": "SAFE", "decision": "ALLOW", "trusted": True, "indicators": [], "note": "Domain is in the trusted organisation list."}
    if u.scheme != "https": inds.append(ind("No HTTPS", "medium", 15, "Connection is not encrypted."))
    if re.fullmatch(r"[\d.]+", host): inds.append(ind("IP-address URL", "high", 30, "Real organisations use domain names, not raw IPs."))
    if host in SHORTENERS: inds.append(ind("URL shortener", "high", 25, "Hides the real destination."))
    if host.count(".") > 3: inds.append(ind("Excessive subdomains", "medium", 10, "Often used to imitate a trusted name."))
    kws = [k for k in ("verify", "secure", "pay", "update", "kyc", "login", "refund", "free", "reward") if k in host + u.path.lower()]
    if kws: inds.append(ind("Suspicious keywords", "medium", min(20, 10 * len(kws)), f"Payment/verification words in URL: {', '.join(kws)}."))
    if any(w in host for w in ("electricity", "bank", "upi", "rbi")): inds.append(ind("Lookalike domain", "high", 25, "Uses an organisation's name but is not its official domain."))
    q = {k.lower() for k in parse_qs(u.query)}
    if q & {"otp", "pin", "cvv", "password"}: inds.append(ind("Credential parameters", "critical", 25, "URL asks for OTP/PIN style data."))
    if u.path.endswith(".apk"): inds.append(ind("APK download", "critical", 30, "Direct app-file download."))
    inds.append(ind("Domain not trusted", "medium", 15, "Domain is not in the trusted organisation list."))
    s = combine(inds)
    return {"url": url, "host": host, "risk_score": s, "risk_level": level(s), "decision": decision(s), "indicators": inds, "trusted": False}

def analyze_upi(payload):
    inds, p = [], payload.strip()
    if not p.lower().startswith("upi://pay"):
        return {"risk_score": 40, "risk_level": "MEDIUM", "decision": "WARN", "indicators": [ind("Not a UPI payment payload", "medium", 25, "Payload does not start with upi://pay.")]}
    q = {k: unquote(v[0]) for k, v in parse_qs(urlparse(p).query).items()}
    vpa, name, note = q.get("pa", "").lower(), q.get("pn", ""), q.get("tn", "")
    try: amt = float(q.get("am", 0))
    except ValueError: amt = 0
    trusted = vpa in TRUSTED_VPAS or vpa in KNOWN_CONTACTS
    if not trusted:
        if re.search(r"support|refund|helpdesk|verify|reward|cashback|lottery|jobs?", vpa): inds.append(ind("Suspicious UPI ID", "high", 20, "UPI ID contains support/refund/reward style wording."))
        if any(w in name.lower() for w in ORG_WORDS): inds.append(ind("Payee name / UPI ID mismatch", "high", 25, f"Payee claims '{name}' but the UPI ID is not registered to that organisation."))
        inds.append(ind("Unknown recipient", "medium", 10, "Recipient is not a saved contact or trusted biller."))
        if amt > AVG_AMOUNT * 3: inds.append(ind("Unusual amount", "medium", 10, f"₹{amt:,.0f} is much higher than the simulated user's usual ₹{AVG_AMOUNT}."))
    if re.search(r"urgent|immediately|fine|penalty|verify", note.lower()): inds.append(ind("Pressure wording in note", "medium", 10, "Transaction note uses urgency/verification language."))
    s = combine(inds)
    return {"recipient": name, "upi_id": vpa, "amount": amt, "currency": q.get("cu", "INR"), "note": note, "risk_score": s, "risk_level": level(s), "decision": decision(s), "indicators": inds, "trusted": trusted}

def analyze_message(text, sender=""):
    t, inds = text.lower(), []
    for n, sev, sc, pat, ex in MSG_RULES:
        if re.search(pat, t): inds.append(ind(n, sev, sc, ex))
    urls, phones, vpas = URL_RE.findall(text), PHONE_RE.findall(text), [v for v in VPA_RE.findall(text) if not v.startswith("http")]
    m = AMT_RE.search(text); amt = float(m.group(1).replace(",", "")) if m else None
    sv = verify_sender(sender, text)
    if sv["status"] != "VERIFIED": inds.append(ind("Unverified sender", "high", 15, sv["detail"]))
    if sv.get("claims_org") and sv["status"] != "VERIFIED": inds.append(ind("Impersonation indicator", "high", 20, "Claims to be an organisation but sender identity cannot be independently verified."))
    url_res = [analyze_url(u) for u in urls]
    if any(r["risk_score"] >= 30 for r in url_res): inds.append(ind("Suspicious payment link", "high", 20, "Link domain is untrusted or shows phishing traits."))
    bad = [v for v in vpas if v.lower() not in KNOWN_CONTACTS and v.lower() not in TRUSTED_VPAS]
    if bad: inds.append(ind("Unknown UPI ID", "medium", 10, f"UPI ID {bad[0]} is not a saved contact or trusted biller."))
    if amt and amt > AVG_AMOUNT * 3 and sv["status"] != "VERIFIED": inds.append(ind("Unusual amount", "medium", 10, f"₹{amt:,.0f} is far above the simulated user's usual ₹{AVG_AMOUNT}."))
    trusted_ctx = sv["status"] == "VERIFIED" and all(r["trusted"] for r in url_res)
    s = combine(inds, 0.35 if trusted_ctx else 1.0)
    names = {i["name"] for i in inds}
    coerce = names & {"Advance fee / deposit demand", "Threat of suspension/penalty", "Job / prize lure"}
    ctx = {
     "WHO": {"q": "Who is receiving the money?", "ok": not bad and sv["status"] == "VERIFIED", "detail": sv["detail"]},
     "WHAT": {"q": "What is being requested?", "ok": "Payment approval request" not in names, "detail": "Approval/collect of money requested." if "Payment approval request" in names else "No unsolicited payment request."},
     "WHY": {"q": "Why is payment requested?", "ok": not coerce, "detail": "Reason relies on fees, threats or lures." if coerce else "No coercive reason found."},
     "WHERE": {"q": "Did it come from a trusted channel?", "ok": trusted_ctx or (sv["status"] == "VERIFIED" and not urls), "detail": "Verified sender and domain." if trusted_ctx else "Channel is unverified."},
     "WHEN": {"q": "Is there unusual urgency?", "ok": "Artificial urgency" not in names, "detail": "Urgent deadline pressure." if "Artificial urgency" in names else "No time pressure."},
     "HOW MUCH": {"q": "Is the amount unusual?", "ok": "Unusual amount" not in names, "detail": f"₹{amt:,.0f} vs usual ₹{AVG_AMOUNT}." if amt else "No amount found."}}
    why = [i["explanation"] for i in sorted(inds, key=lambda i: -i["score"])]
    rec = {"ALLOW": "No major red flags. Still confirm the recipient before paying.",
           "WARN": "Suspicious traits found. Verify via the official app/website before paying.",
           "BLOCK": "Do not pay, click or share any code. Verify only via the official app/website, never via contacts in this message."}[decision(s)]
    return {"risk_score": s, "risk_level": level(s), "decision": decision(s), "indicators": inds, "why": why,
            "extracted": {"sender": sender, "amount": amt, "urls": urls, "phones": phones, "upi_ids": vpas},
            "sender_verification": sv, "url_analysis": url_res, "context": ctx, "recommendation": rec,
            "zero_trust_note": "Even with a correct OTP/PIN, payment requires contextual verification when risk is not low."}

def verify_payment(risk_score, method):
    """Zero-trust gate: credentials alone never suffice."""
    if risk_score < 30: return {"decision": "ALLOW", "message": "Low risk. Simulated payment allowed."}
    if method == "not_verified": return {"decision": "BLOCK", "message": "BLOCKED: you have not independently verified this request. No simulated money was moved."}
    if method in ("official_website", "official_app") and risk_score < 80: return {"decision": "ALLOW", "message": "Verified via an official channel. Simulated payment allowed."}
    if method in ("saved_recipient", "known_contact") and risk_score >= 55: return {"decision": "WARN", "message": "You say the recipient is known, yet the request looks high-risk. Call that contact on a number you already have before paying."}
    return {"decision": "BLOCK" if risk_score >= 80 else "WARN", "message": "Risk too high to trust this claim. Re-verify using the organisation's official app, not links from the message."}

def run_cases(path):
    cases = json.load(open(path, encoding="utf-8")); out = []
    for c in cases:
        r = analyze_message(c["text"], c["sender"]); flagged = r["decision"] != "ALLOW"
        out.append({**c, "risk_score": r["risk_score"], "decision": r["decision"], "correct": flagged == (c["kind"] == "suspicious")})
    tp = sum(1 for o in out if o["kind"] == "suspicious" and o["decision"] != "ALLOW"); fp = sum(1 for o in out if o["kind"] == "legitimate" and o["decision"] != "ALLOW")
    return {"results": out, "total": len(out), "accuracy": round(sum(o["correct"] for o in out) / len(out), 3), "precision": round(tp / (tp + fp), 3) if tp + fp else None, "note": "Computed on the bundled sample set only."}
