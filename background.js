// ============================================================
//  钓鱼拦截 - 后台 Service Worker
//  功能：监听网页导航、查询威胁情报、触发告警
// ============================================================

import { checkDomainThreat, getCacheKey, inspectHost, extractHost, preloadIntelligenceSources, updateAPIKeys, getSourceStatus } from './utils/threat-intel.js';

// ---------- 配置 ----------
const CACHE_TTL_MS = 30 * 60 * 1000; // 缓存 30 分钟
const DEBOUNCE_MS = 500;             // 防抖，避免短时间内重复查询同一域名

// ---------- 运行时状态 ----------
const domainCache = new Map();        // 域名 -> { threat, timestamp }
const pendingQueries = new Map();    // 域名 -> Promise (去重，同一域名只查一次)
let stats = { total: 0, safe: 0, threat: 0, error: 0 };

// 初始化：加载持久化统计 + 预加载情报源
(async () => {
  const [saved] = await Promise.all([
    chrome.storage.local.get('stats'),
    preloadIntelligenceSources()
  ]);
  if (saved.stats) stats = saved.stats;
})();

// ---------- 工具函数 ----------
function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

async function saveStats() {
  await chrome.storage.local.set({ stats });
}

// ---------- 核心：查询威胁情报 ----------
async function queryThreat(domain) {
  // 1. 检查缓存
  const cached = domainCache.get(domain);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL_MS) {
    return cached.threat;
  }

  // 2. 去重：如果同一个域名正在查询中，复用 Promise
  if (pendingQueries.has(domain)) {
    return pendingQueries.get(domain);
  }

  // 3. 发起查询
  const queryPromise = (async () => {
    try {
      const result = await checkDomainThreat(domain);
      domainCache.set(domain, { threat: result, timestamp: Date.now() });

      // cacheKey 用于持久化缓存同步
      const cacheKey = getCacheKey(domain);
      if (result) {
        await chrome.storage.local.set({ [cacheKey]: result });
      }
      return result;
    } catch (err) {
      console.error(`[钓鱼拦截] 查询失败 (${domain}):`, err);
      return null; // 查询失败不拦截
    } finally {
      pendingQueries.delete(domain);
    }
  })();

  pendingQueries.set(domain, queryPromise);
  return queryPromise;
}

// ---------- 告警处理 ----------
function showThreatNotification(domain, threatInfo, tabId) {
  // Chrome 桌面通知
  chrome.notifications.create(`threat-${domain}`, {
    type: 'basic',
    iconUrl: 'images/icon128.png',
    title: '⚠️ 安全告警 - 检测到威胁域名',
    message: `${domain}\n威胁类型: ${threatInfo.threat_type || '未知'}\n来源: ${threatInfo.source}`,
    priority: 2,
    buttons: [{ title: '查看详情' }]
  });

  // 注入告警横幅到页面
  if (tabId) {
    chrome.tabs.sendMessage(tabId, {
      action: 'SHOW_WARNING',
      domain,
      threatInfo
    }).catch(() => {
      // 页面可能还没加载完成，稍后重试
      setTimeout(() => {
        chrome.tabs.sendMessage(tabId, {
          action: 'SHOW_WARNING',
          domain,
          threatInfo
        }).catch(() => {});
      }, 2000);
    });
  }
}

function showSafeNotification(tabId) {
  if (tabId) {
    chrome.tabs.sendMessage(tabId, {
      action: 'SHOW_SAFE'
    }).catch(() => {});
  }
}

// ---------- 监听网页导航 ----------
// 使用 onCommitted 确保用户真的访问了该页面
chrome.webNavigation.onCommitted.addListener(async (details) => {
  // 只处理主框架（顶层页面），忽略 iframe
  if (details.frameId !== 0) return;

  const domain = extractDomain(details.url);
  if (!domain) return;

  // 忽略 Chrome 内部页面
  if (details.url.startsWith('chrome://') ||
      details.url.startsWith('chrome-extension://') ||
      details.url.startsWith('about:') ||
      details.url.startsWith('edge://')) {
    return;
  }

  stats.total++;
  await saveStats();

  console.log(`[钓鱼拦截] 检测域名: ${domain}`);

  // 防抖：短时间内重复导航到同一域名
  const lastCheck = domainCache.get(domain);
  if (lastCheck && (Date.now() - lastCheck.timestamp) < DEBOUNCE_MS) {
    return;
  }

  const threatInfo = await queryThreat(domain);

  if (threatInfo) {
    stats.threat++;
    await saveStats();
    console.warn(`[钓鱼拦截] ⚠️ 威胁域名: ${domain}`, threatInfo);
    showThreatNotification(domain, threatInfo, details.tabId);

    // 更新扩展图标徽章
    chrome.action.setBadgeText({ text: '⚠️', tabId: details.tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#FF0000', tabId: details.tabId });
  } else {
    stats.safe++;
    await saveStats();
    console.log(`[钓鱼拦截] ✓ 安全域名: ${domain}`);
    chrome.action.setBadgeText({ text: '✓', tabId: details.tabId });
    chrome.action.setBadgeBackgroundColor({ color: '#4CAF50', tabId: details.tabId });
  }
});

// ============================================================
//  右键菜单：手动检查域名 / IP
// ============================================================

// 注册右键菜单（安装/更新时）
function registerContextMenus() {
  chrome.contextMenus.removeAll(() => {
    // 检查链接的域名
    chrome.contextMenus.create({
      id: 'check-link',
      title: '检查此链接的威胁情报',
      contexts: ['link']
    });

    // 检查选中的文本（域名/IP）
    chrome.contextMenus.create({
      id: 'check-selection',
      title: '检查选中的域名/IP：“%s”',
      contexts: ['selection']
    });

    // 检查当前页面
    chrome.contextMenus.create({
      id: 'check-page',
      title: '检查当前页面的威胁情报',
      contexts: ['page']
    });

    // 检查图片来源
    chrome.contextMenus.create({
      id: 'check-image',
      title: '检查图片来源的威胁情报',
      contexts: ['image']
    });
  });
}

chrome.runtime.onInstalled.addListener(registerContextMenus);
chrome.runtime.onStartup.addListener(registerContextMenus);

// 右键菜单点击处理
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  let host = '';

  switch (info.menuItemId) {
    case 'check-link':
      host = extractHost(info.linkUrl || '');
      break;
    case 'check-image':
      host = extractHost(info.srcUrl || '');
      break;
    case 'check-selection':
      host = extractHost(info.selectionText || '');
      break;
    case 'check-page':
      host = extractHost(info.pageUrl || (tab && tab.url) || '');
      break;
    default:
      return;
  }

  if (!host) {
    if (tab && tab.id) {
      chrome.tabs.sendMessage(tab.id, {
        action: 'SHOW_CHECK_RESULT',
        error: '未能识别出有效的域名或 IP',
        query: info.selectionText || info.linkUrl || info.srcUrl || ''
      }).catch(() => {});
    }
    return;
  }

  await runManualInspection(host, tab);
});

// 执行手动检查并回传结果
async function runManualInspection(host, tab) {
  // 先在页面上显示"检查中"状态
  if (tab && tab.id) {
    chrome.tabs.sendMessage(tab.id, {
      action: 'SHOW_CHECK_LOADING',
      host
    }).catch(() => {});
  }

  let report;
  try {
    report = await inspectHost(host);
  } catch (err) {
    console.error('[钓鱼拦截] 手动检查失败:', err);
    report = { host, is_threat: false, findings: [], primary: null, error: String(err) };
  }

  // 桌面通知
  if (report.is_threat) {
    chrome.notifications.create(`manual-${host}-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'images/icon128.png',
      title: '⚠️ 检查结果：发现威胁',
      message: `${host}\n${report.primary?.threat_type || '恶意活动'}\n来源: ${report.primary?.source || '未知'}`,
      priority: 2
    });
  } else {
    chrome.notifications.create(`manual-${host}-${Date.now()}`, {
      type: 'basic',
      iconUrl: 'images/icon128.png',
      title: '✓ 检查结果：未发现威胁',
      message: `${host}\n未在威胁情报库中发现记录`,
      priority: 1
    });
  }

  // 页面弹窗展示详细结果
  if (tab && tab.id) {
    chrome.tabs.sendMessage(tab.id, {
      action: 'SHOW_CHECK_RESULT',
      host,
      report
    }).catch(() => {
      setTimeout(() => {
        chrome.tabs.sendMessage(tab.id, {
          action: 'SHOW_CHECK_RESULT',
          host,
          report
        }).catch(() => {});
      }, 1000);
    });
  }
}

// ---------- 通知点击事件 ----------
chrome.notifications.onClicked.addListener((notificationId) => {
  const domain = notificationId.replace('threat-', '');
  // 查找该域名的标签页并激活
  chrome.tabs.query({}, (tabs) => {
    const tab = tabs.find(t => {
      try { return new URL(t.url).hostname === domain; } catch { return false; }
    });
    if (tab) {
      chrome.tabs.update(tab.id, { active: true });
      chrome.windows.update(tab.windowId, { focused: true });
    }
  });
});

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
  if (buttonIndex === 0) {
    chrome.notifications.onClicked.dispatch(notificationId);
  }
});

// ---------- 消息处理：popup 与 content script 通信 ----------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case 'GET_STATS':
      sendResponse(stats);
      break;

    case 'CLEAR_STATS':
      stats = { total: 0, safe: 0, threat: 0, error: 0 };
      domainCache.clear();
      saveStats();
      sendResponse({ success: true });
      break;

    case 'CHECK_DOMAIN':
      (async () => {
        const domain = message.domain;
        if (!domain) {
          sendResponse({ error: 'No domain provided' });
          return;
        }
        const threatInfo = await queryThreat(domain);
        sendResponse({ domain, threatInfo });
      })();
      return true; // 保持异步通道

    case 'INSPECT_HOST':
      (async () => {
        const host = extractHost(message.host || message.input || '');
        if (!host) {
          sendResponse({ error: '未能识别出有效的域名或 IP' });
          return;
        }
        const report = await inspectHost(host);
        sendResponse({ host, report });
      })();
      return true; // 保持异步通道

    case 'GET_DOMAIN_CACHE':
      const cacheList = [];
      domainCache.forEach((value, key) => {
        cacheList.push({ domain: key, ...value });
      });
      sendResponse(cacheList);
      break;

    case 'GET_SOURCE_STATUS':
      sendResponse(getSourceStatus());
      break;

    case 'UPDATE_API_KEYS':
      updateAPIKeys(message.keys || {});
      sendResponse({ success: true });
      break;

    default:
      sendResponse({ error: 'Unknown action' });
  }
});

console.log('[钓鱼拦截] Service Worker 已启动');
