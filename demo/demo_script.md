# UPI Shield: demo and 2-minute script (all data simulated)
1. Overview: "Scams exploit panic, not code. UPI Shield interrupts the payment moment."
2. Click **Start Demo** (about 30s, auto-plays): fake bill message, risk score 92, reasons, sender mismatch (ELECTRICITY-SUPPORT vs official ELECTRICITY-TEST), zero-trust modal, choose "not verified", transaction BLOCKED.
3. Test cases page: **Run all cases**. 5 suspicious are flagged, 3 legitimate are allowed (metrics computed live from the sample set).
4. Simulation page: pick A/C (risky) then B (safe path).
5. Dashboard: totals, distribution, recent actions.
Pitch: Detect (explainable score) -> Verify (sender/link/QR) -> Stop (zero-trust: correct PIN/OTP is not proof; WHO/WHAT/WHY/WHERE/WHEN/HOW MUCH).
Judge Q&A: "Why not just ML?" Rules are explainable and need no data; the novelty is the contextual gate. "False positives?" Trusted sender+domain lowers score; legit cases are allowed; user can verify via an official channel to proceed. "Real money?" No: static analysis and simulated payments only.
