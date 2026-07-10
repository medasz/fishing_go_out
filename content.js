// ============================================================
//  内容脚本 - 页面内告警横幅
//  在网页中注入安全状态 UI
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

  // ---------- 创建告警横幅 ----------
  function createWarningBanner(domain, threatInfo) {
    // 移除旧横幅
    const existing = document.getElementById('fishing-guard-warning');
    if (existing) existing.remove();

    const banner = document.createElement('div');
    banner.id = 'fishing-guard-warning';

    const threatType = threatInfo.threat_type || '未知威胁';
    const source = threatInfo.source || '未知来源';
    const description = threatInfo.description || threatInfo.warnings?.join('；') || '';

    banner.innerHTML = `
      <div class="fg-banner-inner">
        <div class="fg-banner-icon">⚠️</div>
        <div class="fg-banner-content">
          <div class="fg-banner-title">安全告警 - 当前网站可能存在安全风险</div>
          <div class="fg-banner-domain">域名: <strong>${escapeHTML(domain)}</strong></div>
          <div class="fg-banner-detail">
            <span class="fg-tag fg-tag-threat">${escapeHTML(threatType)}</span>
            <span class="fg-tag fg-tag-source">情报源: ${escapeHTML(source)}</span>
          </div>
          ${description ? `<div class="fg-banner-desc">${escapeHTML(description)}</div>` : ''}
          <div class="fg-banner-actions">
            <button class="fg-btn fg-btn-danger" id="fg-btn-back">返回安全页面</button>
            <button class="fg-btn fg-btn-secondary" id="fg-btn-ignore">我了解风险，继续访问</button>
            <button class="fg-btn fg-btn-secondary" id="fg-btn-details">查看详情</button>
          </div>
          <div class="fg-banner-details" id="fg-details-panel" style="display:none;">
            <pre>${escapeHTML(JSON.stringify(threatInfo, null, 2))}</pre>
          </div>
        </div>
      </div>
    `;

    document.body.prepend(banner);

    // 添加页面遮罩（半透明警告层）
    const overlay = document.createElement('div');
    overlay.id = 'fishing-guard-overlay';
    overlay.className = 'fg-overlay';
    document.body.appendChild(overlay);

    // 保留页面原有内容渲染（不破坏 DOM），但添加视觉效果

    // 事件绑定
    document.getElementById('fg-btn-back').addEventListener('click', () => {
      window.history.back();
      // 如果无法后退，关闭标签页
      setTimeout(() => {
        chrome.runtime.sendMessage({ action: 'CLOSE_TAB' });
      }, 500);
    });

    document.getElementById('fg-btn-ignore').addEventListener('click', () => {
      banner.remove();
      if (overlay) overlay.remove();
    });

    document.getElementById('fg-btn-details').addEventListener('click', () => {
      const panel = document.getElementById('fg-details-panel');
      panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
    });
  }

  // ---------- 创建安全标识 ----------
  function createSafeBadge(domain) {
    const existing = document.getElementById('fishing-guard-safe');
    if (existing) existing.remove();

    const badge = document.createElement('div');
    badge.id = 'fishing-guard-safe';
    badge.className = 'fg-safe-badge';
    badge.innerHTML = `
      <span class="fg-safe-icon">🛡️</span>
      <span class="fg-safe-text">安全检测通过</span>
    `;

    document.body.prepend(badge);

    // 3秒后自动消失
    setTimeout(() => {
      badge.classList.add('fg-fade-out');
      setTimeout(() => badge.remove(), 500);
    }, 3000);
  }

  // ---------- HTML 转义 ----------
  function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ---------- 监听后台消息 ----------
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'SHOW_WARNING') {
      whenReady(() => {
        createWarningBanner(message.domain, message.threatInfo);
      });
      sendResponse({ received: true });
    } else if (message.action === 'SHOW_SAFE') {
      whenReady(() => {
        createSafeBadge(message.domain);
      });
      sendResponse({ received: true });
    }
  });

  // ---------- 检测当前页面（页面加载后自检） ----------
  whenReady(async () => {
    const domain = window.location.hostname;
    if (!domain || domain === 'localhost' || domain.match(/^\d+\.\d+\.\d+\.\d+$/)) return;

    // 向后台请求检测
    try {
      const resp = await chrome.runtime.sendMessage({
        action: 'CHECK_DOMAIN',
        domain
      });
      if (resp && resp.threatInfo) {
        createWarningBanner(domain, resp.threatInfo);
      }
    } catch (e) {
      // 静默失败
    }
  });
})();
