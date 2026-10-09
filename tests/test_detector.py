import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import detector as d
CASES = pathlib.Path(__file__).resolve().parents[2] / "sample_data" / "cases.json"

def test_suspicious_blocked():
    r = d.analyze_message("URGENT: pay ₹2499 immediately using the link http://x.example.test/pay or be disconnected", "ELECTRICITY-SUPPORT")
    assert r["decision"] == "BLOCK" and r["indicators"]
def test_legit_allowed():
    assert d.analyze_message("Your electricity bill of ₹640 is generated. Pay via https://electricity.example.test/bills", "ELECTRICITY-TEST")["decision"] == "ALLOW"
def test_otp_request():
    assert any(i["name"] == "Request for OTP/PIN" for i in d.analyze_message("Please share your OTP", "x")["indicators"])
def test_sender_mismatch(): assert d.verify_sender("ELECTRICITY-SUPPORT", "electricity bill")["status"] == "MISMATCH"
def test_urls():
    assert d.analyze_url("http://192.168.1.5/verify?otp=1")["decision"] == "BLOCK"
    assert d.analyze_url("https://electricity.example.test/bills")["trusted"]
def test_upi():
    assert d.analyze_upi("upi://pay?pa=test-electricity@upi&pn=Electricity%20Board&am=2499")["decision"] == "BLOCK"
    assert d.analyze_upi("upi://pay?pa=ravi.kumar@demo&pn=Ravi&am=450")["decision"] == "ALLOW"
def test_score_bounded():
    assert d.analyze_message("urgent blocked share otp install app .apk approve registration fee http://1.2.3.4/x", "")["risk_score"] <= 100
def test_zero_trust(): assert d.verify_payment(90, "not_verified")["decision"] == "BLOCK"
def test_dataset_metrics():
    m = d.run_cases(CASES); print(m["accuracy"], m["precision"]); assert all(r["correct"] for r in m["results"])
