// ============================================================
//  钓鱼拦截 - 后台 Service Worker
//  功能：监听网页导航、查询威胁情报、触发告警
// ============================================================

import { checkDomainThreat, getCacheKey, inspectHost, extractHost, preloadIntelligenceSources, updateAPIKeys, getSourceStatus, applySourceToggles } from './utils/threat-intel.js';

// ---------- 配置 ----------
const CACHE_TTL_MS = 30 * 60 * 1000; // 缓存 30 分钟

// ---------- 运行时状态 ----------
const domainCache = new Map();        // 域名 -> { threat, timestamp }
const pendingQueries = new Map();    // 域名 -> Promise (去重，同一域名只查一次)
const exceptionDomains = new Set();  // 用户手动放行的域名（会话级别）
const whitelist = new Set();         // 持久化白名单（常用安全网站，免检测）
let stats = { total: 0, safe: 0, threat: 0, error: 0 };

// ---------- 预置白名单：常用可信站点（首次安装时写入，之后可自由增删） ----------
const DEFAULT_WHITELIST = [
  // 国内常用
  'baidu.com', 'qq.com', 'weixin.qq.com', 'taobao.com', 'tmall.com',
  'jd.com', 'alipay.com', 'aliyun.com', 'tencent.com', 'bilibili.com',
  'zhihu.com', 'douban.com', 'weibo.com', '163.com', 'sina.com.cn',
  'sohu.com', 'meituan.com', 'douyin.com', 'xiaohongshu.com',
  'gitee.com', 'csdn.net', 'cnblogs.com', 'juejin.cn',
  // 国际常用
  'google.com', 'youtube.com', 'github.com', 'microsoft.com', 'live.com',
  'apple.com', 'icloud.com', 'amazon.com', 'wikipedia.org', 'mozilla.org',
  'cloudflare.com', 'stackoverflow.com', 'gitlab.com', 'npmjs.com',
  'linkedin.com', 'x.com', 'facebook.com', 'openai.com'
];

// 初始化：加载持久化统计 + 预加载情报源 + 加载白名单
// 用 initPromise 暴露初始化完成状态，消息处理在返回前 await 它，
// 避免 Service Worker 冷启动时读到尚未 applySourceToggles 的默认内存状态
const initPromise = (async () => {
  const [saved, keyStore, toggleStore, whitelistStore, initFlag] = await Promise.all([
    chrome.storage.local.get('stats'),
    chrome.storage.local.get('apiKeys'),
    chrome.storage.local.get('sourceEnabled'),
    chrome.storage.local.get('whitelist'),
    chrome.storage.local.get('whitelistInitialized')
  ]);
  await preloadIntelligenceSources();
  if (saved.stats) stats = saved.stats;
  if (keyStore && keyStore.apiKeys) updateAPIKeys(keyStore.apiKeys);
  if (toggleStore && toggleStore.sourceEnabled) applySourceToggles(toggleStore.sourceEnabled);

  if (whitelistStore && Array.isArray(whitelistStore.whitelist)) {
    whitelistStore.whitelist.forEach(d => whitelist.add(String(d).toLowerCase()));
  }

  // 首次安装（从未初始化过）→ 注入预置白名单；之后不再重复注入，尊重用户增删
  if (!initFlag || !initFlag.whitelistInitialized) {
    DEFAULT_WHITELIST.forEach(d => whitelist.add(d));
    await chrome.storage.local.set({
      whitelist: [...whitelist],
      whitelistInitialized: true
    });
    console.log(`[钓鱼拦截] 已注入 ${DEFAULT_WHITELIST.length} 个预置白名单站点`);
  }
})();

// ---------- 工具函数 ----------
function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

// 规范化域名：去协议/路径/端口/用户名，转小写
function normalizeDomain(input) {
  if (!input) return '';
  let d = String(input).trim().toLowerCase();
  d = d.replace(/^https?:\/\//, '');
  d = d.replace(/^[^@]*@/, '');   // 去掉 user@
  d = d.replace(/:\d+$/, '');     // 去掉端口
  d = d.replace(/\/.*$/, '');     // 去掉路径
  d = d.replace(/^\./, '');       // 去掉前导点
  return d;
}

// 白名单匹配（精确 + 子域名）：evil.github.com 命中 github.com
function isWhitelisted(domain) {
  if (!domain) return false;
  const d = domain.toLowerCase();
  if (whitelist.has(d)) return true;
  for (const entry of whitelist) {
    if (d.endsWith('.' + entry)) return true;
  }
  return false;
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

// ---------- 判断是否应跳过检测 ----------
function shouldSkipUrl(url) {
  if (!url) return true;
  return url.startsWith('chrome://') ||
         url.startsWith('chrome-extension://') ||
         url.startsWith('about:') ||
         url.startsWith('edge://') ||
         url.startsWith('moz-extension://');
}

// ---------- 拦截式阻断：在页面加载前重定向到内置警告页 ----------
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // 只处理主框架（顶层页面），忽略 iframe
  if (details.frameId !== 0) return;

  // 忽略浏览器内部页面 / 检测页本身（chrome-extension://）
  if (shouldSkipUrl(details.url)) return;

  const domain = extractDomain(details.url);
  if (!domain) return;

  // 命中白名单（精确或子域名）→ 免检测直接放行
  if (isWhitelisted(domain)) {
    console.log(`[钓鱼拦截] 白名单域名: ${domain}，跳过检测`);
    return;
  }

  // 用户已手动放行此域名 → 直接放行，不查询
  if (exceptionDomains.has(domain)) {
    console.log(`[钓鱼拦截] 用户已放行: ${domain}，跳过拦截`);
    return;
  }

  // 缓存命中：已确认安全 / 威胁，直接出结论（零延迟放行或拦截）
  const lastCheck = domainCache.get(domain);
  if (lastCheck && (Date.now() - lastCheck.timestamp) < CACHE_TTL_MS) {
    if (lastCheck.threat) {
      console.warn(`[钓鱼拦截] ⚠️ 缓存命中威胁，拦截: ${domain}`);
      stats.total++; stats.threat++; await saveStats();
      redirectToBlockedPage(details.tabId, domain, details.url, lastCheck.threat);
      markThreatBadge(details.tabId);
      notifyThreat(domain, lastCheck.threat);
    } else {
      console.log(`[钓鱼拦截] ✓ 缓存命中安全: ${domain}`);
      stats.total++; stats.safe++; await saveStats();
      markSafeBadge(details.tabId);
    }
    return;
  }

  // 未知域名：先转入「安全检测中转页」，目标站不会加载，检测完再决定
  console.log(`[钓鱼拦截] 未知域名，转入检测页: ${domain}`);
  redirectToCheckingPage(details.tabId, domain, details.url);
});

// ---------- 重定向到内置阻断页面 ----------
async function redirectToBlockedPage(tabId, domain, originalUrl, threatInfo) {
  // 将威胁信息暂存到 storage，阻断页通过 domain 读取
  const key = `blocked_${domain}`;
  await chrome.storage.local.set({
    [key]: {
      domain,
      url: originalUrl,
      threatInfo,
      timestamp: Date.now()
    }
  });

  const blockedUrl = chrome.runtime.getURL(
    `blocked.html?domain=${encodeURIComponent(domain)}`
  );

  try {
    await chrome.tabs.update(tabId, { url: blockedUrl });
  } catch (err) {
    console.error('[钓鱼拦截] 重定向到阻断页失败:', err);
  }
}

// ---------- 重定向到内置「安全检测中转页」 ----------
// 该页面不会加载目标站任何资源，检测完成后再由页面决定跳转或拦截
function redirectToCheckingPage(tabId, domain, originalUrl) {
  const checkingUrl = chrome.runtime.getURL(
    `checking.html?domain=${encodeURIComponent(domain)}&target=${encodeURIComponent(originalUrl)}`
  );
  return chrome.tabs.update(tabId, { url: checkingUrl }).catch(err => {
    console.error('[钓鱼拦截] 重定向到检测页失败:', err);
  });
}

// ---------- Badge / 通知 辅助函数 ----------
function markThreatBadge(tabId) {
  chrome.action.setBadgeText({ text: '⚠️', tabId });
  chrome.action.setBadgeBackgroundColor({ color: '#FF0000', tabId });
}

function markSafeBadge(tabId) {
  chrome.action.setBadgeText({ text: '✓', tabId });
  chrome.action.setBadgeBackgroundColor({ color: '#4CAF50', tabId });
}

function notifyThreat(domain, threatInfo) {
  chrome.notifications.create(`threat-${domain}`, {
    type: 'basic',
    iconUrl: 'images/icon128.png',
    title: '⚠️ 安全告警 - 已拦截威胁网站',
    message: `${domain}\n威胁类型: ${threatInfo.threat_type || '未知'}\n来源: ${threatInfo.source}`,
    priority: 2
  });
}

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
  // 'threat-' 前缀 = 自动拦截；'manual-' 前缀 = 右键检查
  const id = notificationId.replace(/^(threat-|manual-)/, '');
  if (!id) return;
  // 尝试拆分 domain 和时间戳
  const dashIdx = id.lastIndexOf('-');
  const domain = dashIdx > 0 ? id.substring(0, dashIdx) : id;
  chrome.tabs.create({ url: `https://urlhaus.abuse.ch/host/${encodeURIComponent(domain)}/` });
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
      (async () => {
        await initPromise;
        sendResponse(stats);
      })();
      return true;

    case 'CLEAR_STATS':
      stats = { total: 0, safe: 0, threat: 0, error: 0 };
      domainCache.clear();
      exceptionDomains.clear();
      saveStats();
      sendResponse({ success: true });
      break;

    case 'GET_WHITELIST':
      sendResponse({ whitelist: [...whitelist] });
      break;

    case 'ADD_WHITELIST':
      (async () => {
        const d = normalizeDomain(message.domain);
        if (!d) { sendResponse({ error: 'Invalid domain' }); return; }
        whitelist.add(d);
        await chrome.storage.local.set({ whitelist: [...whitelist] });
        console.log(`[钓鱼拦截] 加入白名单: ${d}`);
        sendResponse({ success: true, whitelist: [...whitelist] });
      })();
      return true;

    case 'REMOVE_WHITELIST':
      (async () => {
        const d = normalizeDomain(message.domain);
        whitelist.delete(d);
        await chrome.storage.local.set({ whitelist: [...whitelist] });
        console.log(`[钓鱼拦截] 移出白名单: ${d}`);
        sendResponse({ success: true, whitelist: [...whitelist] });
      })();
      return true;

    case 'CLEAR_WHITELIST':
      (async () => {
        whitelist.clear();
        await chrome.storage.local.set({ whitelist: [] });
        sendResponse({ success: true });
      })();
      return true;

    case 'RESET_WHITELIST':
      // 恢复预置白名单（在现有基础上补齐默认站点，不删除用户自定义项）
      (async () => {
        DEFAULT_WHITELIST.forEach(d => whitelist.add(d));
        await chrome.storage.local.set({
          whitelist: [...whitelist],
          whitelistInitialized: true
        });
        sendResponse({ success: true, whitelist: [...whitelist] });
      })();
      return true;

    case 'EXPORT_CONFIG':
      (async () => {
        const store = await chrome.storage.local.get([
          'whitelist', 'whitelistInitialized', 'apiKeys', 'sourceEnabled', 'stats'
        ]);
        const exportData = {
          version: 1,
          exportedAt: new Date().toISOString(),
          whitelist: Array.isArray(store.whitelist) ? store.whitelist : [],
          whitelistInitialized: !!store.whitelistInitialized,
          apiKeys: store.apiKeys || {},
          sourceEnabled: store.sourceEnabled || {},
          stats: store.stats || null
        };
        sendResponse({ success: true, config: exportData });
      })();
      return true;

    case 'IMPORT_CONFIG':
      (async () => {
        const cfg = message.config;
        if (!cfg || typeof cfg !== 'object') {
          sendResponse({ success: false, error: 'Invalid config' });
          return;
        }
        // 白名单
        if (Array.isArray(cfg.whitelist)) {
          whitelist.clear();
          cfg.whitelist.map(String).forEach(d => { if (d) whitelist.add(d.toLowerCase()); });
          await chrome.storage.local.set({ whitelist: [...whitelist], whitelistInitialized: true });
        }
        // API Key
        if (cfg.apiKeys && typeof cfg.apiKeys === 'object') {
          updateAPIKeys(cfg.apiKeys);
          await chrome.storage.local.set({ apiKeys: cfg.apiKeys });
        }
        // 情报源开关
        if (cfg.sourceEnabled && typeof cfg.sourceEnabled === 'object') {
          applySourceToggles(cfg.sourceEnabled);
          await chrome.storage.local.set({ sourceEnabled: cfg.sourceEnabled });
        }
        // 统计（可选）
        if (cfg.stats && typeof cfg.stats === 'object') {
          stats = cfg.stats;
          saveStats();
        }
        sendResponse({ success: true });
      })();
      return true;


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

    case 'CLOSE_TAB':
      (async () => {
        const tabId = message.tabId || (sender.tab && sender.tab.id);
        if (tabId) {
          try { await chrome.tabs.remove(tabId); } catch {}
        }
      })();
      return true;

    case 'GET_SOURCE_STATUS':
      (async () => {
        await initPromise;
        sendResponse(getSourceStatus());
      })();
      return true;

    case 'UPDATE_API_KEYS':
      updateAPIKeys(message.keys || {});
      sendResponse({ success: true });
      break;

    case 'GET_API_KEYS':
      (async () => {
        const store = await chrome.storage.local.get('apiKeys');
        sendResponse(store.apiKeys || {});
      })();
      return true; // 保持异步通道

    case 'UPDATE_SOURCE_TOGGLES':
      (async () => {
        await initPromise;
        applySourceToggles(message.toggles || {});
        await chrome.storage.local.set({ sourceEnabled: message.toggles || {} });
        sendResponse({ success: true });
      })();
      return true;

    case 'GET_BLOCKED_INFO':
      (async () => {
        const domain = message.domain;
        if (!domain) {
          sendResponse({ error: 'No domain' });
          return;
        }
        const data = await chrome.storage.local.get(`blocked_${domain}`);
        const blockedInfo = data[`blocked_${domain}`];
        if (blockedInfo) {
          sendResponse({ domain: blockedInfo.domain, url: blockedInfo.url, threatInfo: blockedInfo.threatInfo });
          // 读取后清理
          await chrome.storage.local.remove(`blocked_${domain}`);
        } else {
          sendResponse({ error: 'No blocked info found' });
        }
      })();
      return true;

    case 'PROCEED_TO_SITE':
      (async () => {
        const targetUrl = message.url;
        const domain = message.domain;
        if (!targetUrl || !domain) {
          sendResponse({ error: 'Missing url or domain' });
          return;
        }
        // 加入例外白名单
        exceptionDomains.add(domain);
        // 缓存中标记为安全，避免再次触发
        domainCache.set(domain, { threat: null, timestamp: Date.now() });
        console.log(`[钓鱼拦截] 用户手动放行: ${domain}`);
        await chrome.tabs.update(message.tabId || sender.tab?.id, { url: targetUrl });
        sendResponse({ success: true });
      })();
      return true;

    case 'REQUEST_CHECK':
      // 检测页发来的检测请求：查询结果并通知检测页
      (async () => {
        const domain = message.domain;
        const target = message.target;
        if (!domain) {
          sendResponse({ error: 'No domain' });
          return;
        }
        const threatInfo = await queryThreat(domain);
        const tid = message.tabId;
        // 用户已在检测过程中跳过/放行 → 放弃拦截，避免把已访问站点弹回
        if (exceptionDomains.has(domain)) {
          stats.total++; stats.safe++; await saveStats();
          if (tid != null) markSafeBadge(tid);
          sendResponse({ domain, threatInfo: null });
          return;
        }
        stats.total++;
        if (threatInfo) {
          stats.threat++;
          await saveStats();
          console.warn(`[钓鱼拦截] ⚠️ 检测页发现威胁: ${domain}`, threatInfo);
          if (tid != null) {
            redirectToBlockedPage(tid, domain, target, threatInfo);
            markThreatBadge(tid);
          }
          notifyThreat(domain, threatInfo);
          sendResponse({ domain, threatInfo });
        } else {
          stats.safe++;
          await saveStats();
          console.log(`[钓鱼拦截] ✓ 检测页安全: ${domain}`);
          if (tid != null) markSafeBadge(tid);
          sendResponse({ domain, threatInfo: null });
        }
      })();
      return true; // 保持异步通道

    case 'PROCEED_FROM_CHECKING':
      // 用户在检测页手动直接跳转 / 检测结果为安全 → 放行目标站
      // 前端已使用 location.replace 直接跳转，这里仅更新缓存/白名单
      (async () => {
        const targetUrl = message.url;
        const domain = message.domain;
        if (!targetUrl || !domain) {
          sendResponse({ error: 'Missing url or domain' });
          return;
        }
        // 加入例外白名单 + 标记为安全，避免再次进入检测页
        exceptionDomains.add(domain);
        domainCache.set(domain, { threat: null, timestamp: Date.now() });
        console.log(`[钓鱼拦截] 用户从检测页放行: ${domain}`);
        const tid = message.tabId || (sender.tab && sender.tab.id);
        if (tid != null) markSafeBadge(tid);
        sendResponse({ success: true });
      })();
      return true; // 保持异步通道

    default:
      sendResponse({ error: 'Unknown action' });
  }
});

console.log('[钓鱼拦截] Service Worker 已启动');
