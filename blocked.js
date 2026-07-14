// ============================================================
//  阻断页面脚本 — 全屏拦截页，页面资源 100% 由扩展控制
// ============================================================

(function () {
  'use strict';

  const domain = new URLSearchParams(location.search).get('domain') || '';

  // 元素
  const elDomain = document.getElementById('info-domain');
  const elType = document.getElementById('info-type');
  const elSource = document.getElementById('info-source');
  const elUrl = document.getElementById('info-url');
  const elDesc = document.getElementById('info-desc');
  const elSubtitle = document.getElementById('subtitle');

  let targetUrl = '';
  let threatInfo = null;

  // ---------- 从 background 获取拦截信息 ----------
  async function loadBlockedInfo() {
    if (!domain) {
      elDomain.textContent = '未知';
      return;
    }

    try {
      const resp = await chrome.runtime.sendMessage({
        action: 'GET_BLOCKED_INFO',
        domain
      });

      if (resp && resp.url) {
        targetUrl = resp.url;
        threatInfo = resp.threatInfo || {};

        elDomain.textContent = domain;
        elType.textContent = threatInfo.threat_type || '未知威胁';
        elSource.textContent = threatInfo.source || '未知来源';
        elUrl.textContent = targetUrl;

        const desc = threatInfo.description || '';
        if (desc) {
          elDesc.style.display = 'block';
          elDesc.textContent = desc;
        }

        // 更新副标题
        elSubtitle.innerHTML = `该网站可能包含 <strong style="color:#da3633">${escapeHTML(elType.textContent)}</strong>，<br>已被钓鱼拦截扩展阻止访问。`;
      } else {
        // 无拦截信息，可能是手动加载了 blocked.html
        elDomain.textContent = domain || '(无)';
        elType.textContent = '信息已过期';
        elSource.textContent = '-';
        elUrl.textContent = '-';
        document.getElementById('btn-proceed').style.display = 'none';
      }
    } catch (err) {
      console.error('获取拦截信息失败:', err);
      elDomain.textContent = domain || '错误';
      elType.textContent = '加载失败';
      elSource.textContent = '-';
      elUrl.textContent = '-';
    }
  }

  // ---------- 返回安全页面 ----------
  document.getElementById('btn-back').addEventListener('click', () => {
    // 尝试使用浏览器后退
    if (window.history.length > 1) {
      window.history.back();
    }
    // 如果后退失败，直接关闭标签页
    setTimeout(() => {
      chrome.runtime.sendMessage({ action: 'CLOSE_TAB' });
    }, 300);
  });

  // ---------- 继续访问（用户手动放行） ----------
  document.getElementById('btn-proceed').addEventListener('click', async () => {
    if (!targetUrl || !domain) return;

    const btn = document.getElementById('btn-proceed');
    btn.textContent = '正在跳转...';
    btn.disabled = true;

    try {
      await chrome.runtime.sendMessage({
        action: 'PROCEED_TO_SITE',
        url: targetUrl,
        domain
      });
      // 跳转成功后，background 会重定向当前标签页
    } catch (err) {
      console.error('跳转失败:', err);
      btn.textContent = '跳转失败，请手动输入网址';
    }
  });

  // ---------- 转义 ----------
  function escapeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str == null ? '' : String(str);
    return div.innerHTML;
  }

  // ---------- 启动 ----------
  loadBlockedInfo();
})();
