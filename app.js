let auditState = {};

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  renderFrameworkOverview();
  renderAuditChecklist();
  renderThreatVectors();
  initModal();
});

// Tab Navigation
function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  const contents = document.querySelectorAll('.tab-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      contents.forEach(c => c.classList.remove('active'));

      tab.classList.add('active');
      const targetId = tab.dataset.tab;
      document.getElementById(targetId).classList.add('active');
    });
  });
}

// Render Framework Controls
function renderFrameworkOverview() {
  const container = document.getElementById('controlsContainer');
  if (!container) return;

  container.innerHTML = BANKING_SECURITY_DATA.domains.map(domain => `
    <div class="domain-section">
      <div class="domain-header">
        <i class="fa-solid ${domain.icon}"></i>
        <h2>${domain.name}</h2>
      </div>
      <p style="color: var(--text-muted); margin-bottom: 1.2rem; font-size: 0.9rem;">${domain.description}</p>
      
      <div class="controls-grid">
        ${domain.controls.map(control => `
          <div class="control-card">
            <div>
              <div class="control-top">
                <span class="control-id">${control.id}</span>
                <span class="severity-pill severity-${control.severity}">${control.severity}</span>
              </div>
              <h3>${control.name}</h3>
              <p>${control.description}</p>
              
              <div class="standards-tags">
                <span class="standard-chip"><i class="fa-solid fa-shield"></i> ${control.asvs}</span>
                <span class="standard-chip"><i class="fa-solid fa-credit-card"></i> ${control.pci}</span>
                <span class="standard-chip"><i class="fa-solid fa-landmark"></i> ${control.fapi}</span>
              </div>
            </div>
            
            <button class="btn-remediation" onclick="openRemediationModal('${control.id}')">
              <i class="fa-solid fa-code"></i> View Remediation Code
            </button>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');
}

// Render Interactive Audit Questionnaire & Calculator
function renderAuditChecklist() {
  const container = document.getElementById('auditListContainer');
  if (!container) return;

  let allControls = [];
  BANKING_SECURITY_DATA.domains.forEach(d => {
    d.controls.forEach(c => {
      allControls.push(c);
      if (!(c.id in auditState)) {
        auditState[c.id] = 'FAIL'; // Default conservative baseline
      }
    });
  });

  container.innerHTML = allControls.map(c => {
    const isPassed = auditState[c.id] === 'PASS';
    return `
      <div class="audit-item">
        <div class="audit-info">
          <h4>[${c.id}] ${c.name}</h4>
          <p>${c.description}</p>
        </div>
        <div class="audit-actions">
          <span class="status-badge ${isPassed ? 'pass' : 'fail'}">
            <i class="fa-solid ${isPassed ? 'fa-circle-check' : 'fa-circle-xmark'}"></i>
            ${isPassed ? 'VERIFIED PASS' : 'AUDIT FAIL'}
          </span>
        </div>
      </div>
    `;
  }).join('');

  updateScoreDial();
}

function updateScoreDial() {
  const total = Object.keys(auditState).length;
  if (total === 0) return;

  const passed = Object.values(auditState).filter(s => s === 'PASS').length;
  const percentage = Math.round((passed / total) * 100);

  const dial = document.getElementById('scoreDial');
  const text = document.getElementById('scoreText');
  const gradeBadge = document.getElementById('complianceGrade');

  if (text) text.innerText = `${percentage}%`;
  if (dial) {
    dial.style.background = `conic-gradient(#10b981 ${percentage * 3.6}deg, rgba(255, 255, 255, 0.08) 0deg)`;
  }

  if (gradeBadge) {
    if (percentage >= 90) {
      gradeBadge.innerText = 'GRADE A+ (BANKING COMPLIANT)';
      gradeBadge.style.color = '#10b981';
    } else if (percentage >= 70) {
      gradeBadge.innerText = 'GRADE B (MODERATE RISK)';
      gradeBadge.style.color = '#f59e0b';
    } else {
      gradeBadge.innerText = 'GRADE F (CRITICAL VULNERABILITIES)';
      gradeBadge.style.color = '#f43f5e';
    }
  }
}

// Render Threat Vectors Tab
function renderThreatVectors() {
  const container = document.getElementById('threatsContainer');
  if (!container) return;

  container.innerHTML = BANKING_SECURITY_DATA.threatVectors.map(t => `
    <div class="control-card" style="margin-bottom: 1.5rem;">
      <div class="control-top">
        <span class="control-id">${t.id}</span>
        <span class="severity-pill severity-${t.severity}">${t.severity}</span>
      </div>
      <h3><i class="fa-solid fa-triangle-exclamation" style="color: var(--accent-amber); margin-right: 8px;"></i> ${t.title}</h3>
      <p style="color: var(--text-sub); margin-bottom: 12px;">${t.description}</p>
      
      <div style="background: rgba(16, 185, 129, 0.08); border-left: 3px solid var(--primary-emerald); padding: 10px 14px; border-radius: 4px; font-size: 0.85rem;">
        <strong style="color: var(--primary-emerald);">BankSec Mitigation:</strong> ${t.mitigation}
      </div>
    </div>
  `).join('');
}

// Modal logic for Code Remediation
function initModal() {
  const overlay = document.getElementById('remediationModal');
  const closeBtn = document.getElementById('modalCloseBtn');

  if (closeBtn) {
    closeBtn.addEventListener('click', () => {
      overlay.classList.remove('active');
    });
  }

  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) overlay.classList.remove('active');
    });
  }
}

function openRemediationModal(controlId) {
  let targetControl = null;
  for (const d of BANKING_SECURITY_DATA.domains) {
    const match = d.controls.find(c => c.id === controlId);
    if (match) {
      targetControl = match;
      break;
    }
  }

  if (!targetControl) return;

  document.getElementById('modalTitle').innerText = `${targetControl.id}: ${targetControl.name}`;
  document.getElementById('modalSubtitle').innerText = targetControl.remediation.title;
  document.getElementById('modalCode').innerText = targetControl.remediation.code;

  document.getElementById('remediationModal').classList.add('active');
}

// Real-Time Security Scanner Logic (Powered by Node.js Backend Engine)
async function runRealtimeScan() {
  const urlInput = document.getElementById('targetUrlInput');
  const targetUrl = urlInput ? urlInput.value.trim() : '';

  if (!targetUrl) {
    alert("Please enter a valid target URL (e.g. https://ai-trading-analyst-mw6zuofd4fpemjkqlmydgg.streamlit.app/ or http://demo.testfire.net)");
    return;
  }

  const resultsArea = document.getElementById('scanResultsArea');
  const consoleLog = document.getElementById('scanConsoleLog');
  const startBtn = document.getElementById('startScanBtn');
  const findingsContainer = document.getElementById('findingsContainer');

  resultsArea.style.display = 'block';
  startBtn.disabled = true;
  startBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Scanning Target...`;
  consoleLog.innerText = `[${new Date().toLocaleTimeString()}] Starting BankSec Real-Time Vulnerability Probe against ${targetUrl}...\n`;

  function log(msg) {
    consoleLog.innerText += `[${new Date().toLocaleTimeString()}] ${msg}\n`;
    consoleLog.scrollTop = consoleLog.scrollHeight;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(targetUrl);
  } catch (err) {
    log(`❌ INVALID URL: ${err.message}`);
    startBtn.disabled = false;
    startBtn.innerHTML = `<i class="fa-solid fa-play"></i> Launch Real-Time Scan`;
    return;
  }

  document.getElementById('resHost').innerText = parsedUrl.hostname;
  log(`📡 Invoking BankSec Backend HTTP/HTTPS Scanner Engine...`);

  try {
    const apiRes = await fetch(`/api/scan?url=${encodeURIComponent(targetUrl)}`);
    const data = await apiRes.json();

    if (data.error) {
      log(`❌ SCAN ERROR: ${data.error}`);
      startBtn.disabled = false;
      startBtn.innerHTML = `<i class="fa-solid fa-play"></i> Launch Real-Time Scan`;
      return;
    }

    log(`✅ Connected to host ${data.host}`);
    log(`HTTP Response: Status ${data.statusCode} (${data.statusMessage}) in ${data.rttMs}ms`);

    // HTTPS Status
    document.getElementById('resHttps').innerText = data.isHttps ? 'YES (TLS Encrypted)' : 'NO (Plain HTTP)';
    document.getElementById('resHttps').style.color = data.isHttps ? '#10b981' : '#f43f5e';
    log(data.isHttps ? `✅ Protocol: HTTPS TLS Encryption active.` : `⚠️ Protocol: Unencrypted HTTP! Vulnerable to MiTM eavesdropping.`);

    // Header Score
    document.getElementById('resHeaderScore').innerText = `${data.headerScore} / 5`;
    log(`📊 Security Header Verification Score: ${data.headerScore} / 5`);

    // Log Headers discovered
    if (data.headers) {
      log(`📄 Headers Inspected: ${Object.keys(data.headers).slice(0, 8).join(', ')}...`);
    }

    // Auto-update Interactive Audit Checklist state dynamically
    // Default baseline for scanned endpoint
    auditState['API-01'] = data.isHttps ? 'PASS' : 'FAIL';
    auditState['API-02'] = (data.headerScore >= 3) ? 'PASS' : 'FAIL';
    auditState['AUTH-01'] = (data.headers && data.headers['content-security-policy']) ? 'PASS' : 'FAIL';
    auditState['AUTH-03'] = (data.headers && data.headers['x-frame-options']) ? 'PASS' : 'FAIL';

    const findings = data.findings || [];

    // Override control status to FAIL if specific finding was detected
    findings.forEach(f => {
      if (f.control && auditState[f.control] !== undefined) {
        auditState[f.control] = 'FAIL';
      }
    });

    // Render Findings UI
    if (findings.length === 0) {
      findingsContainer.innerHTML = `
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--primary-emerald); padding: 1.2rem; border-radius: var(--radius-md); color: var(--primary-emerald); margin-bottom: 1rem;">
          <i class="fa-solid fa-circle-check" style="font-size: 1.2rem; margin-right: 8px;"></i> <strong>Scan Completed Successfully!</strong> No critical HTTP security header or protocol vulnerabilities discovered on this endpoint.
        </div>
      `;
    } else {
      findingsContainer.innerHTML = findings.map(f => `
        <div class="control-card" style="margin-bottom: 1rem;">
          <div class="control-top">
            <span class="control-id">FINDING [Mapped to Control ${f.control}]</span>
            <span class="severity-pill severity-${f.severity}">${f.severity}</span>
          </div>
          <h4 style="font-size: 1rem; font-weight: 700; color: #fff; margin-bottom: 4px;">${f.title}</h4>
          <p style="font-size: 0.85rem; color: var(--text-sub); margin-bottom: 8px;">${f.desc}</p>
          <div style="background: rgba(255,255,255,0.04); padding: 8px 12px; border-radius: 4px; font-size: 0.8rem; color: var(--accent-cyan);">
            <strong>Remediation:</strong> ${f.recommendation}
          </div>
        </div>
      `).join('');
    }

    // Add Audit Synchronization Notification Banner
    findingsContainer.innerHTML += `
      <div style="background: linear-gradient(135deg, rgba(99, 102, 241, 0.15), rgba(6, 182, 212, 0.15)); border: 1px solid var(--accent-indigo); padding: 1rem 1.2rem; border-radius: var(--radius-md); margin-top: 1rem; display: flex; justify-content: space-between; align-items: center;">
        <div>
          <h4 style="font-size: 0.95rem; font-weight: 700; color: #fff; margin-bottom: 2px;"><i class="fa-solid fa-sync" style="color: var(--accent-cyan);"></i> Interactive Audit Sync Complete</h4>
          <p style="font-size: 0.8rem; color: var(--text-sub);">The controls in your <strong>Interactive Audit</strong> tab have been automatically updated to reflect this live scan.</p>
        </div>
        <button class="status-btn pass" onclick="document.querySelector('[data-tab=auditTab]').click()" style="padding: 8px 16px;">
          View Updated Audit <i class="fa-solid fa-arrow-right"></i>
        </button>
      </div>
    `;

    // Update Interactive Audit Score Dial & List View
    updateScoreDial();
    renderAuditChecklist();

    log(`🎉 REAL-TIME SCAN COMPLETED! Interactive Audit tab updated automatically.`);

  } catch (netErr) {
    log(`❌ Backend Connection Failure: ${netErr.message}`);
  } finally {
    startBtn.disabled = false;
    startBtn.innerHTML = `<i class="fa-solid fa-play"></i> Launch Real-Time Scan`;
  }
}

// Export Audit Report
function exportAuditReport() {

  const reportData = {
    timestamp: new Date().toISOString(),
    tool: "BankSec Core v1.0 - Financial Security Auditor",
    complianceScore: document.getElementById('scoreText').innerText,
    auditResults: auditState
  };

  const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `BankSec-Audit-Report-${Date.now()}.json`;
  a.click();
}
