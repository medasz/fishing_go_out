// ============================================================
//  内容脚本 — 右键菜单检查结果弹窗
//  自动拦截已移至 beforeNavigate 阻断页面，此处仅保留手动检查 UI
// ============================================================

(function () {
  'use strict';

  // 避免重复注入
  if (window.__fishingGuardInjected) return;
  window.__fishingGuardInjected = true;

  // ---------- 等待 DOM 就绪 ----------
  function whenReady(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else {
      fn();
    }
  }

  // ---------- 右键检查：结果弹窗 ----------
  function removeCheckPopup() {
    const el = document.getElementById('fishing-guard-check');
    if (el) el.remove();
  }

  function createCheckLoading(host) {
    removeCheckPopup();
    const popup = document.createElement('div');
    popup.id = 'fishing-guard-check';
    popup.className = 'fg-check-popup fg-check-loading';
    popup.innerHTML = `
      <div class="fg-check-header">
        <span class="fg-check-title">威胁情报检查</span>
        <span class="fg-check-close" id="fg-check-close">×</span>
      </div>
      <div class="fg-check-body">
        <div class="fg-check-spinner"></div>
        <div class="fg-check-loading-text">正在查询 <strong>${escapeHTML(host)}</strong> ...</div>
      </div>
    `;
    document.body.appendChild(popup);
    document.getElementById('fg-check-close').addEventListener('click', removeCheckPopup);
  }

  function createCheckResult(host, report, errorMsg) {
    removeCheckPopup();

    const popup = document.createElement('div');
    popup.id = 'fishing-guard-check';

    // 错误情况
    if (errorMsg) {
      popup.className = 'fg-check-popup fg-check-error';
      popup.innerHTML = `
        <div class="fg-check-header">
          <span class="fg-check-title">威胁情报检查</span>
          <span class="fg-check-close" id="fg-check-close">×</span>
        </div>
        <div class="fg-check-body">
          <div class="fg-check-status-icon">❓</div>
          <div class="fg-check-status-text">${escapeHTML(errorMsg)}</div>
        </div>
      `;
      document.body.appendChild(popup);
      document.getElementById('fg-check-close').addEventListener('click', removeCheckPopup);
      return;
    }

    const isThreat = report && report.is_threat;
    const isIP = report && report.is_ip;
    const findings = (report && report.findings) || [];

    popup.className = `fg-check-popup ${isThreat ? 'fg-check-danger' : 'fg-check-safe'}`;

    // 构建 findings 列表
    let findingsHTML = '';
    if (findings.length > 0) {
      findingsHTML = findings.map(f => {
        const desc = f.description || (f.warnings && f.warnings.join('；')) || '';
        const badge = f.is_threat
          ? '<span class="fg-chk-badge fg-chk-badge-danger">威胁</span>'
          : '<span class="fg-chk-badge fg-chk-badge-info">提示</span>';
        return `
          <div class="fg-chk-finding">
            <div class="fg-chk-finding-head">
              ${badge}
              <span class="fg-chk-finding-type">${escapeHTML(f.threat_type || '未知')}</span>
              <span class="fg-chk-finding-src">${escapeHTML(f.source || '')}</span>
            </div>
            ${desc ? `<div class="fg-chk-finding-desc">${escapeHTML(desc)}</div>` : ''}
            ${f.url_count ? `<div class="fg-chk-finding-meta">关联恶意URL: ${f.url_count} 条</div>` : ''}
          </div>
        `;
      }).join('');
    } else {
      findingsHTML = '<div class="fg-chk-empty">未在威胁情报库中发现任何记录</div>';
    }

    popup.innerHTML = `
      <div class="fg-check-header">
        <span class="fg-check-title">威胁情报检查</span>
        <span class="fg-check-close" id="fg-check-close">×</span>
      </div>
      <div class="fg-check-summary">
        <div class="fg-check-status-icon">${isThreat ? '⚠️' : '✓'}</div>
        <div class="fg-check-summary-text">
          <div class="fg-check-verdict">${isThreat ? '发现威胁' : '未发现威胁'}</div>
          <div class="fg-check-host">${isIP ? 'IP' : '域名'}: <strong>${escapeHTML(host)}</strong></div>
        </div>
      </div>
      <div class="fg-check-body">
        ${findingsHTML}
      </div>
      <div class="fg-check-footer">
        <button class="fg-btn fg-btn-secondary" id="fg-chk-report">在 URLhaus 查看</button>
        <button class="fg-btn fg-btn-secondary" id="fg-chk-raw">原始数据</button>
      </div>
      <div class="fg-check-raw" id="fg-check-raw-panel" style="display:none;">
        <pre>${escapeHTML(JSON.stringify(report, null, 2))}</pre>
      </div>
    `;

    document.body.appendChild(popup);

    document.getElementById('fg-check-close').addEventListener('click', removeCheckPopup);
    document.getElementById('fg-chk-report').addEventListener('click', () => {
      window.open(`https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(host)}`, '_blank');
    });
    document.getElementById('fg-chk-raw').addEventListener('click', () => {
      const panel = document.getElementById('fg-check-raw-panel');
      panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
    });

    // 安全结果 8 秒后自动关闭
    if (!isThreat) {
      setTimeout(() => {
        const cur = document.getElementById('fishing-guard-check');
        if (cur === popup) {
          popup.classList.add('fg-fade-out');
          setTimeout(removeCheckPopup, 500);
        }
      }, 8000);
    }
  }

  // ---------- HTML 转义 ----------
  function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str == null ? '' : String(str);
    return div.innerHTML;
  }

  // ---------- 监听后台消息（仅右键检查相关） ----------
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'SHOW_CHECK_LOADING') {
      whenReady(() => {
        createCheckLoading(message.host);
      });
      sendResponse({ received: true });
    } else if (message.action === 'SHOW_CHECK_RESULT') {
      whenReady(() => {
        createCheckResult(message.host, message.report, message.error);
      });
      sendResponse({ received: true });
    }
  });
})();
