
const API = ""; // Same FastAPI server

const $ = (id) => document.getElementById(id);

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  })[ch]);
}

async function apiPost(path, data) {
  const response = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });

  if (!response.ok) {
    throw new Error(`Request failed (${response.status})`);
  }
  return response.json();
}

async function apiGet(path) {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.json();
}

function riskClass(value) {
  return String(value || "").toLowerCase().replace(/[^a-z]/g, "");
}

function decisionClass(value) {
  return String(value || "").toLowerCase();
}

function showError(target, error) {
  target.innerHTML =
    `<div class="error">${escapeHTML(error.message || "Something went wrong.")}
    <br>Check that the FastAPI server is running.</div>`;
}

function renderResult(target, data) {
  const level = data.risk_level || "UNKNOWN";
  const decision = data.decision || "UNKNOWN";
  const score = Number(data.risk_score ?? 0);
  const indicators = Array.isArray(data.indicators) ? data.indicators : [];

  const extracted = data.extracted || {};
  const context = data.context || {};

  const facts = [];

  if (extracted.sender) facts.push(["Sender", extracted.sender]);
  if (extracted.amount != null) facts.push(["Amount", `₹${extracted.amount}`]);
  if (extracted.urls?.length) facts.push(["URLs", extracted.urls.join(", ")]);
  if (extracted.upi_ids?.length) facts.push(["UPI IDs", extracted.upi_ids.join(", ")]);
  if (data.host) facts.push(["Hostname", data.host]);
  if (data.recipient) facts.push(["Recipient", data.recipient]);
  if (data.upi_id) facts.push(["UPI ID", data.upi_id]);
  if (data.amount != null) facts.push(["Amount", `${data.currency || "INR"} ${data.amount}`]);

  const indicatorsHTML = indicators.length
    ? indicators.map(item => `
        <div class="indicator">
          <strong>${escapeHTML(item.name)}
            <span class="pill ${riskClass(item.severity)}">${escapeHTML(item.severity || "INFO")}</span>
          </strong>
          <p>${escapeHTML(item.explanation || "Indicator detected.")}</p>
        </div>`).join("")
    : `<p class="muted">No indicators were returned by the detector. This does not guarantee the content is safe.</p>`;

  const factsHTML = facts.length
    ? `<h3>Extracted details</h3>${facts.map(([label, value]) =>
        `<div class="indicator"><strong>${escapeHTML(label)}</strong><p>${escapeHTML(value)}</p></div>`
      ).join("")}`
    : "";

  const contextHTML = Object.entries(context).length
    ? `<h3>Context checks</h3>${Object.entries(context).map(([key, item]) => `
        <div class="indicator">
          <strong>${escapeHTML(key)} — ${item.ok ? "Passed" : "Review needed"}</strong>
          <p>${escapeHTML(item.q || "")} ${escapeHTML(item.detail || "")}</p>
        </div>`).join("")}`
    : "";

  const reasons = Array.isArray(data.why) ? data.why : [];
  const recommendation = data.recommendation || data.note ||
    "Verify independently before taking action.";

  target.innerHTML = `
    <article class="result-card">
      <div class="result-top">
        <div>
          <p class="eyebrow">ANALYSIS RESULT</p>
          <h2>${escapeHTML(level)} RISK</h2>
          <span class="pill ${decisionClass(decision)}">${escapeHTML(decision)}</span>
        </div>
        <div class="score">${escapeHTML(score)}<small> / 100</small></div>
      </div>

      <div class="result-summary">${escapeHTML(recommendation)}</div>

      <h3>Detected indicators (${indicators.length})</h3>
      ${indicatorsHTML}
      ${factsHTML}
      ${contextHTML}

      ${reasons.length ? `<h3>Why was this flagged?</h3>
        <ul>${reasons.map(reason => `<li>${escapeHTML(reason)}</li>`).join("")}</ul>` : ""}

      <p class="footnote">
        Rule-based result for a simulation. A low score is not proof of legitimacy.
        No payment was made and no URL was opened by this interface.
      </p>
    </article>`;
}

async function analyze(path, payload, target) {
  target.innerHTML = `<article class="panel muted">Analyzing input…</article>`;

  try {
    const data = await apiPost(path, payload);
    renderResult(target, data);
    await refreshDashboard();
  } catch (error) {
    showError(target, error);
  }
}

function switchView(name) {
  document.querySelectorAll(".view").forEach(view => view.classList.add("hidden"));
  $(`view-${name}`).classList.remove("hidden");

  document.querySelectorAll(".nav-item").forEach(button => {
    button.classList.toggle("active", button.dataset.view === name);
  });

  const titles = {
    dashboard: "Security dashboard",
    message: "Message scanner",
    url: "Link scanner",
    upi: "UPI checker"
  };

  $("page-title").textContent = titles[name] || "UPI Shield";
}

document.querySelectorAll(".nav-item").forEach(button => {
  button.addEventListener("click", () => switchView(button.dataset.view));
});

function runMessage(textId, senderId, resultId) {
  const text = $(textId).value.trim();
  const sender = $(senderId).value.trim();

  if (!text) {
    $(resultId).innerHTML = `<div class="error">Enter a message to analyze.</div>`;
    return;
  }

  analyze("/api/analyze/message", { text, sender }, $(resultId));
}

$("quick-analyze").addEventListener("click", () => {
  $("message-text").value = $("quick-message").value;
  $("message-sender").value = $("quick-sender").value;
  switchView("message");
  runMessage("message-text", "message-sender", "message-result");
});

$("message-analyze").addEventListener("click", () => {
  runMessage("message-text", "message-sender", "message-result");
});

$("message-clear").addEventListener("click", () => {
  $("message-text").value = "";
  $("message-sender").value = "";
  $("message-result").innerHTML = "";
});

$("url-analyze").addEventListener("click", () => {
  const url = $("url-text").value.trim();
  if (!url) {
    $("url-result").innerHTML = `<div class="error">Enter a URL to inspect.</div>`;
    return;
  }
  analyze("/api/analyze/url", { url }, $("url-result"));
});

$("upi-analyze").addEventListener("click", () => {
  const payload = $("upi-text").value.trim();
  if (!payload) {
    $("upi-result").innerHTML = `<div class="error">Enter a UPI payload to check.</div>`;
    return;
  }
  analyze("/api/analyze/qr", { payload }, $("upi-result"));
});

function barRow(name, value, max) {
  const percent = max ? Math.round(value / max * 100) : 0;
  return `
    <div class="dist-row">
      <span>${escapeHTML(name)}</span>
      <div class="dist-track">
        <div class="dist-fill ${riskClass(name)}" style="width:${percent}%"></div>
      </div>
      <strong>${value}</strong>
    </div>`;
}

async function refreshDashboard() {
  try {
    const data = await apiGet("/api/dashboard");

    $("total").textContent = data.total ?? 0;
    $("suspicious").textContent = data.suspicious ?? 0;
    $("high-risk").textContent = data.high_risk ?? 0;
    $("legitimate").textContent = data.legitimate ?? 0;

    const distribution = data.distribution || {};
    const entries = Object.entries(distribution);
    const max = Math.max(1, ...entries.map(([, count]) => count));

    $("distribution").innerHTML = entries.length
      ? entries.map(([name, count]) => barRow(name, count, max)).join("")
      : `<p class="muted">No distribution data available.</p>`;

    const recent = data.recent || [];
    $("recent").innerHTML = recent.length
      ? recent.map(item => `
          <tr>
            <td>${escapeHTML(item.time)}</td>
            <td>${escapeHTML(item.type)}</td>
            <td><span class="pill ${riskClass(item.risk)}">${escapeHTML(item.risk)}</span></td>
            <td>${escapeHTML(item.score)}</td>
            <td><span class="pill ${decisionClass(
              item.action === "Blocked" ? "BLOCK" :
              item.action === "Warned" ? "WARN" : "ALLOW"
            )}">${escapeHTML(item.action)}</span></td>
          </tr>`).join("")
      : `<tr><td colspan="5" class="muted">No scans yet. Analyze a sample message to get started.</td></tr>`;
  } catch (error) {
    $("distribution").innerHTML =
      `<p class="muted">Dashboard unavailable. Start the backend and refresh.</p>`;
  }
}

$("refresh-dashboard").addEventListener("click", refreshDashboard);

refreshDashboard();


document.addEventListener("DOMContentLoaded", () => {
  const navButtons = document.querySelectorAll("[data-view]");

  navButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const viewName = button.dataset.view;

      // Hide all screens
      document.querySelectorAll('[id^="view-"]').forEach((view) => {
        view.hidden = true;
      });

      // Show the selected screen
      const selectedView = document.getElementById(`view-${viewName}`);

      if (selectedView) {
        selectedView.hidden = false;
      } else {
        console.error(`Screen not found: view-${viewName}`);
      }

      // Update active sidebar button
      navButtons.forEach((item) => {
        item.classList.toggle("active", item === button);
      });

      // Update page heading
      const titles = {
        dashboard: "Dashboard",
        message: "Message Scanner",
        url: "Link Scanner",
        upi: "UPI Checker",
      };

      const pageTitle = document.getElementById("page-title");
      if (pageTitle) {
        pageTitle.textContent = titles[viewName] || "UPI Shield";
      }
    });
  });
});