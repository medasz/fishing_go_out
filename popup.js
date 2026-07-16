// ============================================================
//  Popup 弹出窗口脚本
//  展示统计信息、当前页面检测状态
// ============================================================

document.addEventListener('DOMContentLoaded', async () => {
  // ---------- 获取统计数据 ----------
  const [stats, sourceStatus] = await Promise.all([
    chrome.runtime.sendMessage({ action: 'GET_STATS' }),
    chrome.runtime.sendMessage({ action: 'GET_SOURCE_STATUS' })
  ]);

  if (stats) {
    document.getElementById('stat-total').textContent = stats.total || 0;
    document.getElementById('stat-safe').textContent = stats.safe || 0;
    document.getElementById('stat-threat').textContent = stats.threat || 0;
  }

  // ---------- 渲染情报源状态 ----------
  if (sourceStatus) {
    const sourceList = document.getElementById('source-list');
    sourceList.innerHTML = Object.entries(sourceStatus).map(([key, s]) => {

      const keyHint = (s.requiresKey && !s.hasKey) ? ' (需配置 API Key)' : '';
      return `<div class="source-item">
        <label class="source-toggle">
          <input type="checkbox" data-key="${key}" ${s.userEnabled ? 'checked' : ''}>
          <span class="source-name">${s.name}${keyHint}</span>
        </label>
      </div>`;
    }).join('');

    // 切换情报源开关（实时保存到 storage 并通知后台）
    sourceList.addEventListener('change', async (e) => {
      const cb = e.target.closest('input[type="checkbox"][data-key]');
      if (!cb) return;
      const toggles = {};
      sourceList.querySelectorAll('input[type="checkbox"][data-key]').forEach(c => {
        toggles[c.dataset.key] = c.checked;
      });
      await chrome.storage.local.set({ sourceEnabled: toggles });
      await chrome.runtime.sendMessage({ action: 'UPDATE_SOURCE_TOGGLES', toggles });
    });
  }

  // ---------- 白名单管理 ----------
  const whitelistList = document.getElementById('whitelist-list');
  const whitelistInput = document.getElementById('whitelist-input');

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function renderWhitelist(list) {
    if (!list || list.length === 0) {
      whitelistList.innerHTML = '<div class="whitelist-empty">暂无白名单，添加常用安全网站可跳过检测</div>';
      return;
    }
    whitelistList.innerHTML = list.map(d =>
      `<div class="whitelist-item">
         <span class="whitelist-domain">${escapeHtml(d)}</span>
         <button class="whitelist-remove" data-domain="${escapeHtml(d)}" title="移除">✕</button>
       </div>`
    ).join('');
  }

  async function refreshWhitelist() {
    const res = await chrome.runtime.sendMessage({ action: 'GET_WHITELIST' });
    if (res && res.whitelist) renderWhitelist(res.whitelist);
  }

  await refreshWhitelist();

  // 添加（输入框）
  document.getElementById('btn-add-whitelist').addEventListener('click', async () => {
    const raw = whitelistInput.value.trim();
    if (!raw) return;
    const res = await chrome.runtime.sendMessage({ action: 'ADD_WHITELIST', domain: raw });
    if (res && res.whitelist) {
      whitelistInput.value = '';
      renderWhitelist(res.whitelist);
    }
  });
  whitelistInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('btn-add-whitelist').click();
  });

  // 添加当前页面域名
  document.getElementById('btn-add-current').addEventListener('click', async () => {
    const [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (currentTab && currentTab.url) {
      try {
        const domain = new URL(currentTab.url).hostname;
        const res = await chrome.runtime.sendMessage({ action: 'ADD_WHITELIST', domain });
        if (res && res.whitelist) renderWhitelist(res.whitelist);
      } catch {}
    }
  });

  // 移除（事件委托）
  whitelistList.addEventListener('click', async (e) => {
    const btn = e.target.closest('.whitelist-remove');
    if (!btn) return;
    const domain = btn.dataset.domain;
    const res = await chrome.runtime.sendMessage({ action: 'REMOVE_WHITELIST', domain });
    if (res && res.whitelist) renderWhitelist(res.whitelist);
  });

  // 清空
  document.getElementById('btn-clear-whitelist').addEventListener('click', async () => {
    const res = await chrome.runtime.sendMessage({ action: 'CLEAR_WHITELIST' });
    if (res && res.success) renderWhitelist([]);
  });

  // 恢复预置
  document.getElementById('btn-reset-whitelist').addEventListener('click', async () => {
    const res = await chrome.runtime.sendMessage({ action: 'RESET_WHITELIST' });
    if (res && res.whitelist) renderWhitelist(res.whitelist);
  });

  // ---------- 加载并保存 API Key 设置 ----------
  const KEY_FIELDS = {
    virustotal: document.getElementById('key-virustotal'),
    alienvault: document.getElementById('key-alienvault'),
    threatbook: document.getElementById('key-threatbook'),
    pulsedive: document.getElementById('key-pulsedive')
  };

  const savedKeys = await chrome.runtime.sendMessage({ action: 'GET_API_KEYS' });
  if (savedKeys) {
    if (savedKeys.virustotal) KEY_FIELDS.virustotal.value = savedKeys.virustotal;
    if (savedKeys.alienvault) KEY_FIELDS.alienvault.value = savedKeys.alienvault;
    if (savedKeys.threatbook) KEY_FIELDS.threatbook.value = savedKeys.threatbook;
    if (savedKeys.pulsedive) KEY_FIELDS.pulsedive.value = savedKeys.pulsedive;
  }

  document.getElementById('btn-save-keys').addEventListener('click', async () => {
    const keys = {
      virustotal: KEY_FIELDS.virustotal.value.trim(),
      alienvault: KEY_FIELDS.alienvault.value.trim(),
      threatbook: KEY_FIELDS.threatbook.value.trim(),
      pulsedive: KEY_FIELDS.pulsedive.value.trim()
    };
    await chrome.storage.local.set({ apiKeys: keys });
    await chrome.runtime.sendMessage({ action: 'UPDATE_API_KEYS', keys });
    const btn = document.getElementById('btn-save-keys');
    const original = btn.textContent;
    btn.textContent = '已保存 ✓';
    setTimeout(() => { btn.textContent = original; }, 1500);
  });

  // ---------- 获取当前标签页 ----------
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const domainEl = document.getElementById('current-domain');
  const statusEl = document.getElementById('current-status');

  if (tab && tab.url) {
    try {
      const domain = new URL(tab.url).hostname;
      domainEl.textContent = domain;

      // 检查特殊页面
      if (tab.url.startsWith('chrome://') ||
          tab.url.startsWith('chrome-extension://') ||
          tab.url === 'about:blank') {
        statusEl.innerHTML = `
          <span class="status-dot dot-gray"></span>
          <span>系统页面，无需检测</span>
        `;
      } else {
        // 查询域名威胁情报
        const result = await chrome.runtime.sendMessage({
          action: 'CHECK_DOMAIN',
          domain
        });

        if (result && result.threatInfo) {
          statusEl.innerHTML = `
            <span class="status-dot dot-danger"></span>
            <span class="status-text status-danger">
              ⚠️ ${result.threatInfo.threat_type || '检测到威胁'}
            </span>
          `;
        } else {
          statusEl.innerHTML = `
            <span class="status-dot dot-safe"></span>
            <span class="status-text status-safe">✓ 安全</span>
          `;
        }
      }
    } catch {
      domainEl.textContent = '无法识别';
      statusEl.innerHTML = `
        <span class="status-dot dot-gray"></span>
        <span>无法检测</span>
      `;
    }
  } else {
    domainEl.textContent = '无活跃标签页';
  }

  // ---------- 清除统计 ----------
  document.getElementById('btn-clear-stats').addEventListener('click', async () => {
    await chrome.runtime.sendMessage({ action: 'CLEAR_STATS' });
    document.getElementById('stat-total').textContent = '0';
    document.getElementById('stat-safe').textContent = '0';
    document.getElementById('stat-threat').textContent = '0';
  });

  // ---------- 举报可疑网站 ----------
  document.getElementById('btn-report').addEventListener('click', async () => {
    const [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (currentTab && currentTab.url) {
      const domain = new URL(currentTab.url).hostname;
      const reportUrl = `https://urlhaus.abuse.ch/host/${encodeURIComponent(domain)}/`;
      chrome.tabs.create({ url: reportUrl });
    }
  });
});
