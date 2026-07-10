// ============================================================
//  Popup 弹出窗口脚本
//  展示统计信息、当前页面检测状态
// ============================================================

document.addEventListener('DOMContentLoaded', async () => {
  // ---------- 获取统计数据 ----------
  const stats = await chrome.runtime.sendMessage({ action: 'GET_STATS' });
  if (stats) {
    document.getElementById('stat-total').textContent = stats.total || 0;
    document.getElementById('stat-safe').textContent = stats.safe || 0;
    document.getElementById('stat-threat').textContent = stats.threat || 0;
  }

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
      const reportUrl = `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(domain)}`;
      chrome.tabs.create({ url: reportUrl });
    }
  });
});
