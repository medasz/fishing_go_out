// ============================================================
//  安全检测中转页脚本 — 进入前不加载目标站，确认后再跳转
// ============================================================

(function () {
  'use strict';

  const params = new URLSearchParams(location.search);
  const domain = params.get('domain') || '';
  const targetUrl = params.get('target') || '';

  // 元素
  const elDomain = document.getElementById('info-domain');
  const elType = document.getElementById('info-type');
  const elSource = document.getElementById('info-source');
  const elUrl = document.getElementById('info-url');
  const elDesc = document.getElementById('info-desc');

  const stateLoading = document.getElementById('state-loading');
  const stateSafe = document.getElementById('state-safe');
  const stateThreat = document.getElementById('state-threat');

  const btnBack = document.getElementById('btn-back');
  const btnProceed = document.getElementById('btn-proceed');
  const btnSkip = document.getElementById('btn-skip');

  const actionPanel = document.getElementById('action-panel');
  const checkingIcon = document.getElementById('checking-icon');

  let currentTabId = null;
  let checkResolved = false;   // 检测是否已出结果
  let proceedRequested = false; // 是否已发起跳转（防止重复）

  elDomain.textContent = domain || '-';
  elUrl.textContent = targetUrl || '-';

  // ---------- 状态切换 ----------
  function showState(state) {
    stateLoading.classList.add('hidden');
    stateSafe.classList.add('hidden');
    stateThreat.classList.add('hidden');
    state.classList.remove('hidden');

    // 统一操作按钮区域：加载时只显示「跳过检测」，结果后显示「返回」+「仍要访问」
    if (state === stateLoading) {
      actionPanel.classList.add('loading');
      btnSkip.classList.remove('hidden');
      btnBack.classList.add('hidden');
      btnProceed.classList.add('hidden');
      checkingIcon.className = 'checking-icon';
      checkingIcon.textContent = '🛡️';
    } else {
      actionPanel.classList.remove('loading');
      btnSkip.classList.add('hidden');
      btnBack.classList.remove('hidden');
      btnProceed.classList.remove('hidden');
      if (state === stateSafe) {
        checkingIcon.className = 'checking-icon safe';
        checkingIcon.textContent = '✓';
      } else if (state === stateThreat) {
        checkingIcon.className = 'checking-icon threat';
        checkingIcon.textContent = '⚠️';
      }
    }
  }


  function fillThreatInfo(threatInfo) {
    threatInfo = threatInfo || {};
    elType.textContent = threatInfo.threat_type || '未知威胁';
    elSource.textContent = threatInfo.source || '未知来源';
    const desc = threatInfo.description || '';
    if (desc) {
      elDesc.style.display = 'block';
      elDesc.textContent = desc;
    }
  }

  // ---------- 返回安全页面 ----------
  btnBack.addEventListener('click', () => {
    if (window.history.length > 1) {
      window.history.back();
    }
    setTimeout(() => {
      chrome.runtime.sendMessage({ action: 'CLOSE_TAB' });
    }, 300);
  });

  // ---------- 仍要访问（手动直接跳转） ----------
  btnProceed.addEventListener('click', () => {
    if (proceedRequested) return;
    proceedRequested = true;
    btnProceed.textContent = '正在跳转...';
    btnProceed.disabled = true;

    // 使用 replace 不留历史，防止后退时回到检测页再次触发拦截
    if (targetUrl) location.replace(targetUrl);

    // 异步通知 background 更新缓存/白名单
    chrome.runtime.sendMessage({
      action: 'PROCEED_FROM_CHECKING',
      url: targetUrl,
      domain: domain,
      tabId: currentTabId
    }).catch(() => {});
  });

  // ---------- 发起检测 ----------
  async function requestCheck() {
    if (!domain || !targetUrl) {
      showState(stateThreat);
      fillThreatInfo({ threat_type: '参数缺失', source: '-' });
      btnProceed.disabled = false;
      return;
    }

    try {
      const resp = await chrome.runtime.sendMessage({
        action: 'REQUEST_CHECK',
        domain: domain,
        target: targetUrl
      });

      checkResolved = true;

      if (resp && resp.threatInfo) {
        // 威胁
        showState(stateThreat);
        fillThreatInfo(resp.threatInfo);
        // 允许手动跳转
        btnProceed.disabled = false;
      } else if (resp && resp.error) {
        // 检测失败：按安全处理，但允许用户自行决定
        showState(stateSafe);
        btnProceed.disabled = false;
        // 自动放行（检测失败不拦截）
        doProceed();
      } else {
        // 安全
        showState(stateSafe);
        btnProceed.disabled = false;
        doProceed();
      }
    } catch (err) {
      console.error('[检测页] 请求检测失败:', err);
      showState(stateSafe);
      btnProceed.disabled = false;
      doProceed();
    }
  }

  // 安全时自动跳转（无需用户点击）
  function doProceed() {
    if (proceedRequested) return;
    proceedRequested = true;
    btnProceed.textContent = '正在跳转...';
    if (btnSkip) { btnSkip.disabled = true; btnSkip.textContent = '正在跳转...'; }
    // 使用 replace 不留历史，避免后退时回到检测页再次触发检测
    if (targetUrl) location.replace(targetUrl);
    // 异步通知 background 更新缓存/白名单（不阻塞跳转）
    chrome.runtime.sendMessage({
      action: 'PROCEED_FROM_CHECKING',
      url: targetUrl,
      domain: domain,
      tabId: currentTabId
    }).catch(() => {});
  }

  // 检测过程中「跳过检测，直接访问」：行为等同放行
  if (btnSkip) {
    btnSkip.addEventListener('click', doProceed);
  }

  // ---------- 启动 ----------
  // 拿到当前 tabId（用于跳转时指定）
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0]) currentTabId = tabs[0].id;
    requestCheck();
  });
})();
