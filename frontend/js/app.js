/**
 * FILE NAME: app.js
 * PURPOSE: Main Application Controller for UI interaction, Charts, Authentication Gateway, and Analysis Rendering.
 */

let classificationChart = null;
let indicatorsChart = null;
let trendChart = null;
let currentUser = null;

document.addEventListener("DOMContentLoaded", async () => {
  await checkAuthStatus();
});

// ==========================================
// AUTHENTICATION GATEWAY CONTROLLER
// ==========================================

async function checkAuthStatus() {
  try {
    currentUser = await API.getCurrentUser();
  } catch (e) {
    currentUser = null;
  }
  updateGatewayUI();
}

function updateGatewayUI() {
  const gateway = document.getElementById("auth-gateway");
  const appContainer = document.getElementById("app-container");
  const userNameHeader = document.getElementById("header-user-name");
  const userRoleHeader = document.getElementById("header-user-role");

  if (currentUser) {
    // Authenticated: Hide Login Gateway & Show Dashboard Suite
    if (gateway) gateway.classList.add("hidden");
    if (appContainer) appContainer.classList.remove("hidden");
    if (userNameHeader) userNameHeader.textContent = currentUser.username;
    if (userRoleHeader) userRoleHeader.textContent = currentUser.role || "SOC Analyst";

    // Load Dashboard content
    refreshDashboard();
    loadAwareness();
    loadHistory();
  } else {
    // Unauthenticated: Show Login Gateway & Keep Dashboard Locked
    if (gateway) gateway.classList.remove("hidden");
    if (appContainer) appContainer.classList.add("hidden");
  }
}

function switchGatewayTab(tab) {
  const tabLogin = document.getElementById("gate-tab-login");
  const tabReg = document.getElementById("gate-tab-register");
  const formLogin = document.getElementById("gate-form-login");
  const formReg = document.getElementById("gate-form-register");
  const err = document.getElementById("gate-error");
  if (err) err.classList.add("hidden");

  if (tab === "login") {
    tabLogin.className = "flex-1 pb-2.5 text-blue-400 border-b-2 border-blue-500 transition";
    tabReg.className = "flex-1 pb-2.5 text-slate-400 hover:text-slate-200 transition";
    formLogin.classList.remove("hidden");
    formReg.classList.add("hidden");
  } else {
    tabReg.className = "flex-1 pb-2.5 text-blue-400 border-b-2 border-blue-500 transition";
    tabLogin.className = "flex-1 pb-2.5 text-slate-400 hover:text-slate-200 transition";
    formReg.classList.remove("hidden");
    formLogin.classList.add("hidden");
  }
}

async function handleGatewayLogin(event) {
  event.preventDefault();
  const u = document.getElementById("gate-login-user").value.trim();
  const p = document.getElementById("gate-login-pass").value;
  const err = document.getElementById("gate-error");
  const errMsg = document.getElementById("gate-error-msg");

  try {
    const res = await API.login(u, p);
    API.setToken(res.token);
    currentUser = { username: res.username, role: res.role, user_id: res.user_id };
    updateGatewayUI();
  } catch (e) {
    if (errMsg) errMsg.textContent = e.message;
    if (err) err.classList.remove("hidden");
  }
}

async function handleGatewayRegister(event) {
  event.preventDefault();
  const u = document.getElementById("gate-reg-user").value.trim();
  const p = document.getElementById("gate-reg-pass").value;
  const r = document.getElementById("gate-reg-role").value.trim() || "Cybersecurity Analyst";
  const err = document.getElementById("gate-error");
  const errMsg = document.getElementById("gate-error-msg");

  try {
    const res = await API.register(u, p, r);
    API.setToken(res.token);
    currentUser = { username: res.username, role: res.role, user_id: res.user_id };
    updateGatewayUI();
  } catch (e) {
    if (errMsg) errMsg.textContent = e.message;
    if (err) err.classList.remove("hidden");
  }
}

async function handleGatewayLogout() {
  await API.logout();
  currentUser = null;
  updateGatewayUI();
}

// ==========================================
// NAVIGATION & DASHBOARD CONTROLLER
// ==========================================

function switchTab(tabId) {
  document.querySelectorAll(".tab-content").forEach(el => el.classList.add("hidden"));
  document.querySelectorAll(".nav-btn").forEach(el => {
    el.classList.remove("bg-blue-600", "text-white");
    el.classList.add("text-slate-300");
  });

  const activeTab = document.getElementById(`tab-${tabId}`);
  const activeNav = document.getElementById(`nav-${tabId}`);
  if (activeTab) activeTab.classList.remove("hidden");
  if (activeNav) {
    activeNav.classList.add("bg-blue-600", "text-white");
    activeNav.classList.remove("text-slate-300");
  }

  if (tabId === "dashboard") refreshDashboard();
  if (tabId === "history") loadHistory();
}

function clearForm() {
  document.getElementById("email-form").reset();
  document.getElementById("results-container").classList.add("hidden");
  document.getElementById("results-empty").classList.remove("hidden");
}

async function handleEmailSubmit(event) {
  event.preventDefault();
  const btn = document.getElementById("btn-analyze");
  btn.disabled = true;
  btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...`;

  const payload = {
    sender: document.getElementById("input-sender").value.trim(),
    display_name: document.getElementById("input-display-name").value.trim() || null,
    subject: document.getElementById("input-subject").value.trim(),
    body: document.getElementById("input-body").value.trim(),
    urls: document.getElementById("input-urls").value.trim() || "",
    attachment_name: document.getElementById("input-attachment").value.trim() || ""
  };

  try {
    const result = await API.analyzeEmail(payload);
    renderAnalysisResult(result);
  } catch (error) {
    alert("Analysis Error: " + error.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i class="fa-solid fa-radar"></i> Analyze Email`;
  }
}

function renderAnalysisResult(res) {
  document.getElementById("results-empty").classList.add("hidden");
  const container = document.getElementById("results-container");
  container.classList.remove("hidden");

  const score = res.risk_score;
  const scoreVal = document.getElementById("score-value");
  const scoreCircle = document.getElementById("score-circle");
  const badge = document.getElementById("classification-badge");

  scoreVal.textContent = score;
  document.getElementById("res-subject").textContent = res.subject;
  document.getElementById("res-domain").textContent = `Sender Domain: ${res.sender_domain || "Unknown"}`;
  document.getElementById("res-rule-score").textContent = res.rule_score.toFixed(1);
  document.getElementById("res-ml-score").textContent = res.ml_score !== null ? `${res.ml_score.toFixed(1)}%` : "N/A";
  document.getElementById("res-analysis-id").textContent = `ID: ${res.analysis_id}`;

  badge.textContent = res.classification;
  badge.className = "px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider";

  if (res.classification === "HIGH RISK / LIKELY PHISHING") {
    badge.classList.add("badge-phishing");
    scoreCircle.className = "w-20 h-20 rounded-full border-4 border-red-500 text-red-400 flex flex-col items-center justify-center text-center bg-red-500/10";
  } else if (res.classification === "SUSPICIOUS") {
    badge.classList.add("badge-suspicious");
    scoreCircle.className = "w-20 h-20 rounded-full border-4 border-amber-500 text-amber-400 flex flex-col items-center justify-center text-center bg-amber-500/10";
  } else if (res.classification === "LOW RISK") {
    badge.classList.add("badge-low");
    scoreCircle.className = "w-20 h-20 rounded-full border-4 border-blue-500 text-blue-400 flex flex-col items-center justify-center text-center bg-blue-500/10";
  } else {
    badge.classList.add("badge-safe");
    scoreCircle.className = "w-20 h-20 rounded-full border-4 border-emerald-500 text-emerald-400 flex flex-col items-center justify-center text-center bg-emerald-500/10";
  }

  const explList = document.getElementById("res-explanations");
  explList.innerHTML = "";
  (res.explanation || []).forEach(exp => {
    const li = document.createElement("li");
    li.className = "flex items-start gap-2 text-slate-300";
    li.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-amber-400 mt-0.5"></i> <span>${escapeHtml(exp)}</span>`;
    explList.appendChild(li);
  });

  const recList = document.getElementById("res-recommendations");
  recList.innerHTML = "";
  (res.recommendations || []).forEach(rec => {
    const li = document.createElement("li");
    li.className = "flex items-start gap-2";
    li.innerHTML = `<i class="fa-solid fa-shield-check text-emerald-400 mt-0.5"></i> <span>${escapeHtml(rec)}</span>`;
    recList.appendChild(li);
  });

  const senderDiv = document.getElementById("res-sender-breakdown");
  const s = res.sender_analysis;
  senderDiv.innerHTML = `
    <div><span class="text-slate-400">Address:</span> <span class="font-mono text-white">${escapeHtml(s.sender || "None")}</span></div>
    <div><span class="text-slate-400">Domain Length:</span> ${s.domain_length} chars | <span class="text-slate-400">Subdomains:</span> ${s.subdomain_count}</div>
    <div><span class="text-slate-400">Lookalike Pattern:</span> <span class="${s.has_lookalike_patterns ? 'text-red-400 font-bold' : 'text-emerald-400'}">${s.has_lookalike_patterns ? 'DETECTED' : 'None'}</span></div>
    <div><span class="text-slate-400">Display Mismatch:</span> <span class="${s.has_mismatched_display_name ? 'text-amber-400 font-bold' : 'text-emerald-400'}">${s.has_mismatched_display_name ? 'YES' : 'Aligned'}</span></div>
  `;

  const attachDiv = document.getElementById("res-attachment-breakdown");
  const a = res.attachment_analysis;
  if (a) {
    attachDiv.innerHTML = `
      <div><span class="text-slate-400">Filename:</span> <span class="font-mono text-white">${escapeHtml(a.filename)}</span></div>
      <div><span class="text-slate-400">Extension:</span> <span class="font-mono font-bold text-amber-400">${a.extension}</span></div>
      <div><span class="text-slate-400">Double Extension:</span> <span class="${a.is_double_extension ? 'text-red-400 font-bold' : 'text-emerald-400'}">${a.is_double_extension ? 'DETECTED' : 'No'}</span></div>
      <div><span class="text-slate-400">Executable/Script:</span> <span class="${a.is_executable_or_script ? 'text-red-400 font-bold' : 'text-emerald-400'}">${a.is_executable_or_script ? 'YES' : 'No'}</span></div>
    `;
  } else {
    attachDiv.innerHTML = `<span class="text-slate-500 italic">No attachment attached to this email.</span>`;
  }

  const urlDiv = document.getElementById("res-url-list");
  urlDiv.innerHTML = "";
  if (res.url_analyses && res.url_analyses.length > 0) {
    res.url_analyses.forEach(u => {
      const uCard = document.createElement("div");
      uCard.className = "p-3 rounded-lg bg-slate-900 border border-cyberBorder space-y-1";
      uCard.innerHTML = `
        <div class="flex items-center justify-between">
          <span class="font-mono text-xs text-blue-400 truncate max-w-sm">${escapeHtml(u.url)}</span>
          <span class="text-[10px] px-2 py-0.5 rounded ${u.risk_score >= 20 ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400'}">Risk: ${u.risk_score}</span>
        </div>
        <div class="text-[11px] text-slate-400">
          Hostname: <span class="text-slate-200">${escapeHtml(u.hostname)}</span> | Scheme: <span class="text-slate-200">${u.scheme}</span> | IP Hostname: <span class="${u.is_ip_address ? 'text-red-400 font-bold' : 'text-slate-200'}">${u.is_ip_address ? 'YES' : 'No'}</span>
        </div>
      `;
      urlDiv.appendChild(uCard);
    });
  } else {
    urlDiv.innerHTML = `<span class="text-slate-500 italic">No embedded URLs identified.</span>`;
  }
}

async function handleURLInspect(event) {
  event.preventDefault();
  const urlInput = document.getElementById("single-url-input").value.trim();
  const resDiv = document.getElementById("url-inspect-result");
  resDiv.classList.remove("hidden");
  resDiv.innerHTML = `<p class="text-xs text-slate-400"><i class="fa-solid fa-spinner fa-spin"></i> Inspecting URL string...</p>`;

  try {
    const res = await API.analyzeURL(urlInput);
    resDiv.innerHTML = `
      <div class="p-4 rounded-xl border ${res.risk_score >= 20 ? 'border-red-500/30 bg-red-500/5' : 'border-emerald-500/30 bg-emerald-500/5'} space-y-3">
        <div class="flex items-center justify-between">
          <span class="text-sm font-bold text-white">URL Risk Score: <span class="${res.risk_score >= 20 ? 'text-red-400' : 'text-emerald-400'}">${res.risk_score}/100</span></span>
          <span class="text-xs px-2.5 py-1 rounded-full font-bold ${res.risk_score >= 20 ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'}">${res.risk_score >= 20 ? 'SUSPICIOUS' : 'LOW RISK'}</span>
        </div>
        <div class="grid grid-cols-2 gap-2 text-xs text-slate-300">
          <div><span class="text-slate-400">Hostname:</span> <span class="font-mono text-white">${escapeHtml(res.hostname)}</span></div>
          <div><span class="text-slate-400">Scheme:</span> ${res.scheme}</div>
          <div><span class="text-slate-400">Raw IP:</span> ${res.is_ip_address ? '<span class="text-red-400 font-bold">YES</span>' : 'No'}</div>
          <div><span class="text-slate-400">Shortener Pattern:</span> ${res.is_shortened_pattern ? '<span class="text-amber-400 font-bold">YES</span>' : 'No'}</div>
          <div><span class="text-slate-400">Subdomains:</span> ${res.subdomain_count}</div>
          <div><span class="text-slate-400">Suspicious Keywords:</span> ${res.suspicious_keywords_found.join(", ") || "None"}</div>
        </div>
        <div class="pt-2 border-t border-cyberBorder">
          <h5 class="text-xs font-bold text-slate-300 mb-1">Static Findings:</h5>
          <ul class="space-y-1 text-xs">
            ${res.findings.map(f => `<li class="flex items-start gap-1.5"><i class="fa-solid fa-circle-info text-blue-400 mt-0.5"></i> <span>${escapeHtml(f.description)}</span></li>`).join("")}
          </ul>
        </div>
      </div>
    `;
  } catch (err) {
    resDiv.innerHTML = `<p class="text-xs text-red-400">Error: ${escapeHtml(err.message)}</p>`;
  }
}

async function refreshDashboard() {
  try {
    const stats = await API.getDashboardStats();
    document.getElementById("stat-total").textContent = stats.total_emails_analyzed;
    document.getElementById("stat-phishing").textContent = stats.likely_phishing_count;
    document.getElementById("stat-suspicious").textContent = stats.suspicious_count;
    document.getElementById("stat-safe").textContent = stats.safe_count + stats.low_risk_count;
    document.getElementById("stat-avg").textContent = stats.average_risk_score.toFixed(1);

    renderDashboardCharts(stats);
  } catch (err) {
    console.error("Dashboard refresh error:", err);
  }
}

function renderDashboardCharts(stats) {
  const ctxClass = document.getElementById("classificationChart");
  if (ctxClass) {
    if (classificationChart) classificationChart.destroy();
    classificationChart = new Chart(ctxClass, {
      type: "doughnut",
      data: {
        labels: ["High Risk Phishing", "Suspicious", "Low Risk", "Safe"],
        datasets: [{
          data: [
            stats.classification_distribution["HIGH RISK / LIKELY PHISHING"] || 0,
            stats.classification_distribution["SUSPICIOUS"] || 0,
            stats.classification_distribution["LOW RISK"] || 0,
            stats.classification_distribution["SAFE"] || 0
          ],
          backgroundColor: ["#ef4444", "#f59e0b", "#3b82f6", "#10b981"],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 12, font: { size: 10 } } }
        }
      }
    });
  }

  const ctxInd = document.getElementById("indicatorsChart");
  if (ctxInd) {
    if (indicatorsChart) indicatorsChart.destroy();
    const indLabels = (stats.top_indicators || []).map(i => i.type);
    const indCounts = (stats.top_indicators || []).map(i => i.count);

    indicatorsChart = new Chart(ctxInd, {
      type: "bar",
      data: {
        labels: indLabels.length > 0 ? indLabels : ["CONTENT", "URL", "SENDER", "ATTACHMENT"],
        datasets: [{
          label: "Occurrences",
          data: indCounts.length > 0 ? indCounts : [0, 0, 0, 0],
          backgroundColor: "#8b5cf6",
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { display: false } },
          y: { ticks: { color: "#94a3b8", font: { size: 10 } }, grid: { color: "#1f2d4d" } }
        }
      }
    });
  }

  const ctxTrend = document.getElementById("trendChart");
  if (ctxTrend) {
    if (trendChart) trendChart.destroy();
    const trendDates = (stats.recent_trend || []).map(t => t.date);
    const trendTotals = (stats.recent_trend || []).map(t => t.total);
    const trendPhish = (stats.recent_trend || []).map(t => t.phishing);

    trendChart = new Chart(ctxTrend, {
      type: "line",
      data: {
        labels: trendDates.length > 0 ? trendDates : ["Day 1", "Day 2", "Day 3"],
        datasets: [
          {
            label: "Total Emails",
            data: trendTotals.length > 0 ? trendTotals : [0, 0, 0],
            borderColor: "#3b82f6",
            backgroundColor: "rgba(59, 130, 246, 0.1)",
            tension: 0.3,
            fill: true
          },
          {
            label: "Phishing",
            data: trendPhish.length > 0 ? trendPhish : [0, 0, 0],
            borderColor: "#ef4444",
            backgroundColor: "rgba(239, 68, 68, 0.1)",
            tension: 0.3,
            fill: true
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#94a3b8", boxWidth: 10, font: { size: 10 } } }
        },
        scales: {
          x: { ticks: { color: "#94a3b8", font: { size: 9 } }, grid: { display: false } },
          y: { ticks: { color: "#94a3b8", font: { size: 9 } }, grid: { color: "#1f2d4d" } }
        }
      }
    });
  }
}

async function loadHistory() {
  const filter = document.getElementById("history-filter") ? document.getElementById("history-filter").value : "";
  const search = document.getElementById("history-search") ? document.getElementById("history-search").value : "";
  try {
    const list = await API.getHistory(filter, search);
    const tbody = document.getElementById("history-tbody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="text-center p-4 text-slate-500">No triage history records found.</td></tr>`;
      return;
    }

    list.forEach(item => {
      const tr = document.createElement("tr");
      tr.className = "hover:bg-slate-900/50 transition";
      
      let badgeClass = "badge-safe";
      if (item.classification === "HIGH RISK / LIKELY PHISHING") badgeClass = "badge-phishing";
      else if (item.classification === "SUSPICIOUS") badgeClass = "badge-suspicious";
      else if (item.classification === "LOW RISK") badgeClass = "badge-low";

      tr.innerHTML = `
        <td class="p-3 font-mono text-[11px] text-blue-400">${item.analysis_id}</td>
        <td class="p-3 font-mono text-slate-300 truncate max-w-[140px]">${escapeHtml(item.sender_domain || item.sender)}</td>
        <td class="p-3 text-white truncate max-w-[200px]">${escapeHtml(item.subject)}</td>
        <td class="p-3 font-bold">${item.risk_score}</td>
        <td class="p-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${badgeClass}">${item.classification}</span></td>
        <td class="p-3 text-[11px] text-slate-400">${item.created_at}</td>
        <td class="p-3 text-right space-x-2">
          <button onclick="viewHistoryDetail('${item.analysis_id}')" class="text-blue-400 hover:text-blue-300" title="View"><i class="fa-solid fa-eye"></i></button>
          <button onclick="deleteHistoryItem('${item.analysis_id}')" class="text-red-400 hover:text-red-300" title="Delete"><i class="fa-solid fa-trash-can"></i></button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load history:", err);
  }
}

function filterHistory() {
  loadHistory();
}

async function deleteHistoryItem(id) {
  if (!confirm(`Are you sure you want to remove analysis record ${id}?`)) return;
  try {
    await API.deleteAnalysis(id);
    await loadHistory();
    await refreshDashboard();
  } catch (e) {
    alert("Delete failed: " + e.message);
  }
}

async function viewHistoryDetail(id) {
  try {
    const detail = await API.getAnalysisDetail(id);
    switchTab("analyzer");
    renderAnalysisResult({
      analysis_id: detail.analysis_id,
      sender_domain: detail.sender_domain,
      subject: detail.subject,
      risk_score: detail.risk_score,
      rule_score: detail.rule_score,
      ml_score: detail.ml_score,
      classification: detail.classification,
      explanation: detail.explanation,
      recommendations: detail.recommendations,
      sender_analysis: {
        sender: detail.sender,
        domain: detail.sender_domain,
        domain_length: (detail.sender_domain || "").length,
        subdomain_count: 1,
        has_lookalike_patterns: false,
        has_mismatched_display_name: false
      },
      attachment_analysis: detail.has_attachment ? {
        filename: detail.attachment_name,
        extension: detail.attachment_name.split('.').pop(),
        is_double_extension: false,
        is_executable_or_script: false
      } : null,
      url_analyses: detail.url_analyses || []
    });
  } catch (e) {
    alert("Failed to load detail: " + e.message);
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
