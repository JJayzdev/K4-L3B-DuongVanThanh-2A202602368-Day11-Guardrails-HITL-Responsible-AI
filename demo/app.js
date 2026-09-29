/**
 * VinBank Guardrails & Responsible AI Dashboard Logic
 * Connects directly to local server.py APIs:
 * - GET  /api/status
 * - POST /api/evaluate
 * - POST /api/output-check
 * - POST /api/egress
 * - POST /api/rate-limit
 */

// Toast notification helper
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warning' ? '⚠️' : 'ℹ️';
  toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}

// Format bytes
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Escape HTML
function escapeHtml(str) {
  return (str || '').replace(/[&<>"']/g, function(m) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
  });
}

// ----------------------------------------------------
// Navigation Tab Switching
// ----------------------------------------------------
function initTabs() {
  const tabs = document.querySelectorAll('.nav-tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const targetId = tab.getAttribute('data-tab');
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');

      document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
      });
      const activePane = document.getElementById(targetId);
      if (activePane) activePane.classList.add('active');
    });
  });
}

// ----------------------------------------------------
// API 1: GET /api/status (System Stats & Overview)
// ----------------------------------------------------
async function fetchStatus() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderStatus(data);
  } catch (err) {
    console.error('Failed to fetch status:', err);
  }
}

function renderStatus(data) {
  // Provider badges
  const blueBadge = document.getElementById('blueProviderBadge');
  if (blueBadge && data.blue) {
    blueBadge.innerHTML = `<span class="dot"></span><span>Blue: ${escapeHtml(data.blue)}</span>`;
  }
  const redBadge = document.getElementById('redProviderBadge');
  if (redBadge && data.red) {
    redBadge.innerHTML = `<span class="dot"></span><span>Red: ${escapeHtml(data.red)}</span>`;
  }

  // Key Top Metrics
  const safeStat = document.getElementById('statSafeQueries');
  if (safeStat && data.defense) {
    safeStat.textContent = `${data.defense.safe_total - data.defense.safe_blocked} / ${data.defense.safe_total}`;
  }

  const attackStat = document.getElementById('statAttackBlocked');
  if (attackStat && data.defense) {
    attackStat.textContent = `${data.defense.attack_blocked} / ${data.defense.attack_total}`;
  }

  const redLeakStat = document.getElementById('statRedLeaks');
  if (redLeakStat && data.red_team) {
    redLeakStat.textContent = `${data.red_team.unsafe_leaked}`;
  }

  const rateBlockStat = document.getElementById('statRateBlocked');
  if (rateBlockStat && data.defense) {
    rateBlockStat.textContent = `${data.defense.rate_blocked} / ${data.defense.rate_sent}`;
  }

  // Runtime Stats
  const runtimeTotal = document.getElementById('runtimeTotal');
  if (runtimeTotal && data.runtime) runtimeTotal.textContent = data.runtime.total;

  const runtimeBlocked = document.getElementById('runtimeBlocked');
  if (runtimeBlocked && data.runtime) runtimeBlocked.textContent = data.runtime.blocked;

  const runtimeRedacted = document.getElementById('runtimeRedacted');
  if (runtimeRedacted && data.runtime) runtimeRedacted.textContent = data.runtime.redacted;

  // Artifacts Table
  const artifactsTbody = document.getElementById('artifactsTableBody');
  if (artifactsTbody && data.artifacts) {
    artifactsTbody.innerHTML = data.artifacts.map(art => `
      <tr>
        <td><code>${escapeHtml(art.name)}</code></td>
        <td>
          <span class="badge ${art.exists ? 'badge-allow' : 'badge-block'}">
            ${art.exists ? '✓ EXISTS' : '✗ MISSING'}
          </span>
        </td>
        <td>${art.exists ? formatBytes(art.bytes) : '0 B'}</td>
      </tr>
    `).join('');
  }

  // Audit Log Table
  renderAuditTable(data.runtime?.audit || []);
}

function renderAuditTable(auditList) {
  const auditTbody = document.getElementById('auditTableBody');
  if (!auditTbody) return;
  if (auditList.length === 0) {
    auditTbody.innerHTML = `<tr><td colspan="3" style="text-align:center; color:var(--text-dim); padding:1.5rem;">Chưa có sự kiện kiểm tra nào trong phiên chạy hiện tại.</td></tr>`;
    return;
  }
  auditTbody.innerHTML = auditList.slice().reverse().map(item => `
    <tr>
      <td style="max-width:320px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(item.input)}">
        ${escapeHtml(item.input)}
      </td>
      <td>
        <span class="badge ${item.layer ? 'badge-block' : 'badge-allow'}">
          ${item.layer ? escapeHtml(item.layer) : 'ALLOWED'}
        </span>
      </td>
      <td style="max-width:350px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text-muted);" title="${escapeHtml(item.response)}">
        ${escapeHtml(item.response)}
      </td>
    </tr>
  `).join('');
}

// ----------------------------------------------------
// API 2: POST /api/evaluate (Pipeline Evaluation)
// ----------------------------------------------------
async function evaluatePipeline() {
  const inputEl = document.getElementById('evalInputText');
  const callModelEl = document.getElementById('evalCallModelCheck');
  const btn = document.getElementById('evalSubmitBtn');
  const resultBox = document.getElementById('evalResultBox');
  const traceBox = document.getElementById('evalTraceContainer');
  const statusBadge = document.getElementById('evalStatusBadge');

  const text = (inputEl.value || '').trim();
  if (!text) {
    showToast('Vui lòng nhập nội dung cần kiểm tra guardrails!', 'warning');
    return;
  }

  const callModel = callModelEl ? callModelEl.checked : false;
  btn.disabled = true;
  btn.innerHTML = `<span class="live-indicator"></span> Đang phân tích...`;
  resultBox.textContent = 'Đang đưa payload qua các lớp bảo vệ VinBank Guardrails...';

  try {
    const res = await fetch('/api/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, call_model: callModel })
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    // Render Status
    if (data.blocked) {
      statusBadge.className = 'badge badge-block';
      if (data.layer === 'blue_model_refusal') {
        statusBadge.innerHTML = `🛡️ BLUE MODEL TỪ CHỐI (REFUSED)`;
        showToast('Blue Model đã phát hiện và từ chối cung cấp thông tin mật!', 'warning');
      } else {
        statusBadge.innerHTML = `🛡️ CHẶN BỞI [${escapeHtml(data.layer || 'GUARDRAIL')}]`;
        showToast('Phát hiện vi phạm: Yêu cầu đã bị chặn!', 'error');
      }
    } else {
      statusBadge.className = 'badge badge-allow';
      statusBadge.innerHTML = `✓ CHO PHÉP (SAFE)`;
      showToast('Yêu cầu an toàn và hợp lệ!', 'success');
    }

    // Render Final Response
    resultBox.textContent = data.response || '(Không có phản hồi)';

    // Render Trace Stepper
    if (data.trace && Array.isArray(data.trace)) {
      traceBox.innerHTML = data.trace.map((step, idx) => {
        let badgeClass = 'badge-neutral';
        if (step.status === 'ALLOW') badgeClass = 'badge-allow';
        else if (step.status === 'BLOCK') badgeClass = 'badge-block';
        else if (step.status === 'REDACT') badgeClass = 'badge-redact';
        else if (step.status === 'CALLED') badgeClass = 'badge-info';

        return `
          <div class="trace-step">
            <div class="trace-step-left">
              <span class="step-num">${idx + 1}</span>
              <span class="step-name">${escapeHtml(step.layer)}</span>
            </div>
            <span class="badge ${badgeClass}">${escapeHtml(step.status)}</span>
          </div>
        `;
      }).join('');
    }

    // Refresh global metrics & audit
    fetchStatus();
  } catch (err) {
    console.error('Eval error:', err);
    resultBox.textContent = `Lỗi gọi API: ${err.message}`;
    showToast(`Lỗi: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `Kiểm tra Guardrails`;
  }
}

// ----------------------------------------------------
// API 3: POST /api/output-check (PII & Secret Redaction)
// ----------------------------------------------------
async function checkOutputRedaction() {
  const inputEl = document.getElementById('outputInputText');
  const btn = document.getElementById('outputCheckBtn');
  const resultBox = document.getElementById('outputResultBox');
  const issuesList = document.getElementById('outputIssuesList');
  const statusBadge = document.getElementById('outputStatusBadge');

  const text = (inputEl.value || '').trim();
  if (!text) {
    showToast('Vui lòng nhập nội dung cần kiểm tra che giấu dữ liệu!', 'warning');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = `<span class="live-indicator"></span> Đang lọc PII...`;

  try {
    const res = await fetch('/api/output-check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    // Render Status
    if (!data.safe) {
      statusBadge.className = 'badge badge-redact';
      statusBadge.innerHTML = `⚠️ PHÁT HIỆN DỮ LIỆU NHẠY CẢM (${(data.issues || []).length})`;
      showToast('Đã phát hiện và làm mờ (redact) dữ liệu nhạy cảm!', 'warning');
    } else {
      statusBadge.className = 'badge badge-allow';
      statusBadge.innerHTML = `✓ AN TOÀN (SAFE)`;
      showToast('Nội dung an toàn, không chứa PII hoặc secrets!', 'success');
    }

    // Render Issues tags
    if (data.issues && data.issues.length > 0) {
      issuesList.innerHTML = data.issues.map(iss => `
        <span class="badge badge-block">⚠️ ${escapeHtml(iss)}</span>
      `).join(' ');
    } else {
      issuesList.innerHTML = `<span class="badge badge-allow">✓ Không phát hiện thông tin nhạy cảm</span>`;
    }

    // Highlight [REDACTED] in result text
    let safeHtml = escapeHtml(data.redacted || '');
    safeHtml = safeHtml.replace(/\[REDACTED\]/g, `<span class="redacted-highlight">[REDACTED]</span>`);
    resultBox.innerHTML = safeHtml;

    fetchStatus();
  } catch (err) {
    console.error('Output check error:', err);
    resultBox.textContent = `Lỗi: ${err.message}`;
    showToast(`Lỗi: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `Kiểm tra & Che giấu (Redact)`;
  }
}

// ----------------------------------------------------
// API 4: POST /api/egress (Data Egress Firewall)
// ----------------------------------------------------
async function checkEgressFirewall() {
  const destEl = document.getElementById('egressDestination');
  const payloadEl = document.getElementById('egressPayload');
  const btn = document.getElementById('egressCheckBtn');
  const resultBox = document.getElementById('egressResultBox');
  const statusBadge = document.getElementById('egressStatusBadge');

  const destination = (destEl.value || '').trim();
  const payload = (payloadEl.value || '').trim();

  if (!destination) {
    showToast('Vui lòng nhập URL đích đến (Destination URL)!', 'warning');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = `<span class="live-indicator"></span> Đang kiểm tra tường lửa...`;

  try {
    const res = await fetch('/api/egress', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ destination, payload })
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    if (data.allowed) {
      statusBadge.className = 'badge badge-allow';
      statusBadge.innerHTML = `✓ ALLOWED (CHO PHÉP TRUYỀN)`;
      resultBox.innerHTML = `<span style="color:var(--color-success)">[ALLOW] Lưu lượng truyền đi hợp lệ.</span>\n- Điểm đến: ${escapeHtml(destination)}\n- Payload: Tuân thủ quy định bảo mật VinBank Egress Policy.`;
      showToast('Cho phép truyền dữ liệu!', 'success');
    } else {
      statusBadge.className = 'badge badge-block';
      statusBadge.innerHTML = `✗ BLOCKED (CHẶN NGUY CƠ RÒ RỈ)`;
      resultBox.innerHTML = `<span style="color:var(--color-danger)">[BLOCK] Tường lửa Egress đã chặn gói tin!</span>\n- Lý do: URL đích không thuộc domain VinBank được cấp phép, hoặc payload chứa secrets/thông tin nhạy cảm.`;
      showToast('Cảnh báo: Tường lửa đã chặn dữ liệu truyền ra ngoài!', 'error');
    }
  } catch (err) {
    console.error('Egress check error:', err);
    resultBox.textContent = `Lỗi: ${err.message}`;
    showToast(`Lỗi: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `Kiểm tra Egress Firewall`;
  }
}

// ----------------------------------------------------
// API 5: POST /api/rate-limit (Sliding Window Simulator)
// ----------------------------------------------------
async function testRateLimit() {
  const countEl = document.getElementById('rateCountInput');
  const maxEl = document.getElementById('rateMaxInput');
  const btn = document.getElementById('rateTestBtn');
  const resultBox = document.getElementById('rateResultBox');
  const meterFillPass = document.getElementById('meterFillPass');
  const meterFillBlock = document.getElementById('meterFillBlock');
  const passLabel = document.getElementById('meterPassLabel');
  const blockLabel = document.getElementById('meterBlockLabel');

  const count = parseInt(countEl.value, 10) || 5;
  const maximum = parseInt(maxEl.value, 10) || 3;

  btn.disabled = true;
  btn.innerHTML = `<span class="live-indicator"></span> Đang gửi ${count} requests...`;

  try {
    const res = await fetch('/api/rate-limit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ count, maximum })
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const passPct = (data.passed / data.sent) * 100;
    const blockPct = (data.blocked / data.sent) * 100;

    meterFillPass.style.width = `${passPct}%`;
    meterFillBlock.style.width = `${blockPct}%`;
    passLabel.textContent = `Cho qua: ${data.passed} (${Math.round(passPct)}%)`;
    blockLabel.textContent = `Bị chặn: ${data.blocked} (${Math.round(blockPct)}%)`;

    resultBox.textContent = JSON.stringify(data, null, 2);
    showToast(`Hoàn tất: ${data.passed} passed, ${data.blocked} blocked`, data.blocked > 0 ? 'warning' : 'success');

    fetchStatus();
  } catch (err) {
    console.error('Rate limit error:', err);
    resultBox.textContent = `Lỗi: ${err.message}`;
    showToast(`Lỗi: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = `Kích hoạt mô phỏng Rate Limit`;
  }
}

// Preset setup
function setEvalPreset(text) {
  const el = document.getElementById('evalInputText');
  if (el) el.value = text;
}

function setOutputPreset(text) {
  const el = document.getElementById('outputInputText');
  if (el) el.value = text;
}

function setEgressPreset(dest, payload) {
  const destEl = document.getElementById('egressDestination');
  const payloadEl = document.getElementById('egressPayload');
  if (destEl) destEl.value = dest;
  if (payloadEl) payloadEl.value = payload;
}

// Auto init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  fetchStatus();

  // Auto refresh stats every 10 seconds
  setInterval(fetchStatus, 10000);
});
