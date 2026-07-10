// ============================================================
//  威胁情报查询模块
//  支持多个情报源，自动降级
// ============================================================

// ---------- 情报源 API Key 配置 ----------
// 可选：填入你在对应平台申请的免费 API Key 以启用相关情报源
const API_KEYS = {
  phishtank: '',   // 申请地址: https://www.phishtank.com/register.php
  alienvault: '',  // 申请地址: https://otx.alienvault.com/ (留空则使用公开 API)
  abuseipdb: ''    // 申请地址: https://www.abuseipdb.com/ (仅 IP 查询)
};

// ---------- Phishing Army 块列表缓存 ----------
let phishingArmyBlocklist = new Set();
let phishingArmyLastUpdate = 0;
const PHISHING_ARMY_CACHE_TTL = 30 * 60 * 1000; // 30 分钟更新一次

/**
 * 从 phishing.army 下载最新块列表并缓存
 */
async function refreshPhishingArmyBlocklist() {
  if (Date.now() - phishingArmyLastUpdate < PHISHING_ARMY_CACHE_TTL) return;
  try {
    const resp = await fetch('https://phishing.army/download/phishing_army_blocklist.txt', {
      signal: AbortSignal.timeout(15000)
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const text = await resp.text();
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    phishingArmyBlocklist = new Set(lines.map(l => l.toLowerCase()));
    phishingArmyLastUpdate = Date.now();
    console.log(`[Phishing Army] 块列表已更新: ${phishingArmyBlocklist.size} 条`);
  } catch (err) {
    console.warn(`[Phishing Army] 块列表下载失败: ${err.message}`);
  }
}

// ---------- 情报源配置 ----------
const INTEL_SOURCES = {
  // URLhaus - 恶意软件分发 URL 数据库 (免费，无需 API Key)
  urlhaus: {
    name: 'URLhaus',
    endpoint: 'https://urlhaus-api.abuse.ch/v1/host/',
    enabled: true,
    timeout: 10000,
    check: async (domain) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);

      try {
        const resp = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ host: domain }),
          signal: controller.signal
        });
        clearTimeout(timer);

        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const data = await resp.json();
        if (data.query_status === 'ok' && data.url_count > 0) {
          // 聚合威胁类型
          const threatTypes = new Set();
          const recentUrls = [];

          data.urls.forEach(entry => {
            if (entry.threat) threatTypes.add(entry.threat);
            if (entry.url) recentUrls.push(entry.url);
          });

          // 判断黑名单状态
          const blacklists = data.blacklists || {};
          const blockedBy = Object.entries(blacklists)
            .filter(([, status]) => status === 'blacklisted')
            .map(([name]) => name);

          if (threatTypes.size > 0 || blockedBy.length > 0) {
            return {
              is_threat: true,
              source: 'URLhaus',
              domain,
              threat_type: [...threatTypes].join(', ') || '恶意活动',
              url_count: data.url_count,
              blocked_by: blockedBy,
              recent_urls: recentUrls.slice(0, 5),
              first_seen: data.firstseen || null,
              last_seen: data.lastseen || null,
              description: buildDescription(threatTypes, blockedBy, data.url_count)
            };
          }
        }
        return null; // 无威胁
      } catch (err) {
        console.warn(`[URLhaus] 查询失败: ${err.message}`);
        return null;
      }
    }
  },

  // Phishing Army — 开源钓鱼域名块列表 (免费，无需 Key)
  phishing_army: {
    name: 'Phishing Army',
    enabled: true,
    check: async (domain) => {
      if (isIP(domain)) return null; // 块列表不带 IP
      await refreshPhishingArmyBlocklist();
      // 精确匹配：完整域名
      if (phishingArmyBlocklist.has(domain.toLowerCase())) {
        return {
          is_threat: true,
          source: 'Phishing Army',
          domain,
          threat_type: '钓鱼/欺诈域名',
          description: `该域名已收录于 Phishing Army 开源钓鱼块列表`,
          confidence: 'high'
        };
      }
      // 模糊匹配：父级域名
      const parts = domain.split('.');
      for (let i = 1; i < parts.length - 1; i++) {
        const parent = parts.slice(i).join('.').toLowerCase();
        if (phishingArmyBlocklist.has(parent)) {
          return {
            is_threat: true,
            source: 'Phishing Army',
            domain,
            threat_type: '钓鱼/欺诈子域名',
            description: `父级域名 ${parent} 已被 Phishing Army 收录`,
            confidence: 'high'
          };
        }
      }
      return null;
    }
  },

  // PhishTank — 钓鱼 URL 社区数据库 (免费，需申请 App Key)
  phishtank: {
    name: 'PhishTank',
    endpoint: 'https://checkurl.phishtank.com/checkurl/',
    enabled: false,  // 填入 API Key 后启用
    timeout: 10000,
    check: async (host) => {
      const key = API_KEYS.phishtank;
      if (!key || isIP(host)) return null;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);

      try {
        const resp = await fetch('https://checkurl.phishtank.com/checkurl/', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            url: `http://${host}/`,
            format: 'json',
            app_key: key
          }),
          signal: controller.signal
        });
        clearTimeout(timer);

        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();

        if (data.results && data.results.in_database && data.results.valid) {
          return {
            is_threat: true,
            source: 'PhishTank',
            domain: host,
            threat_type: '钓鱼网站',
            phish_id: data.results.phish_id || null,
            phish_detail_url: data.results.phish_detail_url || '',
            verified: data.results.verified || false,
            verified_at: data.results.verified_at || null,
            description: `该域名已被 PhishTank 收录为钓鱼网站${data.results.verified ? '(已验证)' : '(待验证)'}`
          };
        }
        return null;
      } catch (err) {
        console.warn(`[PhishTank] 查询失败: ${err.message}`);
        return null;
      }
    }
  },

  // AlienVault OTX — 开源威胁情报社区 (公开 API，免 Key也有基础配额)
  alienvault_otx: {
    name: 'AlienVault OTX',
    enabled: true,
    timeout: 10000,
    check: async (host) => {
      const key = API_KEYS.alienvault;
      const headers = key ? { 'X-OTX-API-KEY': key } : {};

      const indicatorType = isIP(host) ? 'IPv4' : 'domain';
      const url = `https://otx.alienvault.com/api/v1/indicators/${indicatorType}/${encodeURIComponent(host)}/general`;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);

      try {
        const resp = await fetch(url, { headers, signal: controller.signal });
        clearTimeout(timer);

        if (resp.status === 404) return null; // 无此 indicator
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const data = await resp.json();

        // 收集威胁标签
        const pulseCount = data.pulse_info?.count || 0;
        const pulses = data.pulse_info?.pulses || [];
        const tags = new Set();
        pulses.forEach(p => (p.tags || []).forEach(t => tags.add(t)));

        // 高置信度威胁标签
        const threatTags = ['malware', 'phishing', 'c2', 'botnet', 'ransomware',
          'exploit', 'trojan', 'backdoor', 'spam', 'scam', 'fraud', 'malicious'];
        const matchedThreats = [...tags].filter(t =>
          threatTags.some(tt => t.toLowerCase().includes(tt))
        );

        // 如果有关联脉冲且包含威胁标签，判定为威胁
        if (pulseCount > 0 && matchedThreats.length > 0) {
          return {
            is_threat: true,
            source: 'AlienVault OTX',
            domain: host,
            threat_type: matchedThreats.join(', '),
            pulse_count: pulseCount,
            all_tags: [...tags].slice(0, 20),
            description: pulseCount > 0
              ? `OTX 社区 ${pulseCount} 条威胁情报关联${matchedThreats.length > 0 ? '，标签: ' + matchedThreats.slice(0, 5).join('、') : ''}`
              : null,
            confidence: pulseCount >= 3 ? 'high' : 'medium'
          };
        }

        // 即使不判定为威胁，也返回脉冲信息（供右键检查展示）
        if (pulseCount > 0) {
          return {
            is_threat: false,
            source: 'AlienVault OTX',
            domain: host,
            threat_type: '情报关联',
            pulse_count: pulseCount,
            all_tags: [...tags].slice(0, 20),
            description: pulseCount > 0
              ? `OTX 社区 ${pulseCount} 条关联记录，但未命中高置信度威胁标签`
              : '无威胁记录',
            confidence: 'info'
          };
        }

        return null;
      } catch (err) {
        console.warn(`[AlienVault OTX] 查询失败: ${err.message}`);
        return null;
      }
    }
  },

  // 本地启发式检测 (最后兜底)
  heuristic: {
    name: '启发式检测',
    enabled: true,
    check: async (host) => {
      // IP 和域名走不同的启发式规则
      return isIP(host) ? ipHeuristicCheck(host) : heuristicCheck(host);
    }
  }
};

// ---------- 主机类型判断 ----------
/**
 * 判断字符串是否为 IPv4 地址
 */
export function isIPv4(str) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(str);
  if (!m) return false;
  return m.slice(1).every(n => Number(n) >= 0 && Number(n) <= 255);
}

/**
 * 判断字符串是否为 IPv6 地址（简化匹配）
 */
export function isIPv6(str) {
  const s = str.replace(/^\[|\]$/g, ''); // 去掉可能的方括号
  return /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(s) && s.includes(':');
}

/**
 * 判断是否为 IP 地址 (v4 或 v6)
 */
export function isIP(str) {
  return isIPv4(str) || isIPv6(str);
}

/**
 * 从任意输入文本中提取域名或 IP
 * 支持：完整URL、带端口的host、纯域名/IP、带空格的文本
 * @param {string} input
 * @returns {string} - 提取出的 host，失败返回空字符串
 */
export function extractHost(input) {
  if (!input) return '';
  let text = input.trim();

  // 尝试作为 URL 解析
  try {
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(text)) {
      return new URL(text).hostname;
    }
    // 补全协议再试
    const u = new URL('http://' + text);
    // 校验 hostname 合法性
    if (u.hostname && (u.hostname.includes('.') || isIP(u.hostname))) {
      return u.hostname;
    }
  } catch {
    // 忽略，走正则兜底
  }

  // 正则兜底：从文本中抓取 IPv4 或域名
  const ipMatch = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  if (ipMatch && isIPv4(ipMatch[0])) return ipMatch[0];

  const domainMatch = text.match(/\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/);
  if (domainMatch) return domainMatch[0].toLowerCase();

  return '';
}

// ---------- IP 启发式检测 ----------
function ipHeuristicCheck(ip) {
  const warnings = [];

  if (isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;

    // 私有/保留地址提示
    const isPrivate =
      a === 10 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      a === 127 ||
      (a === 169 && b === 254) ||
      a === 0 ||
      a >= 224; // 组播/保留

    if (a === 127) {
      warnings.push('本地回环地址 (localhost)');
    } else if (isPrivate) {
      warnings.push('内网/保留 IP 地址');
    }

    // 直接以裸 IP 访问网站，本身是钓鱼常见特征
    warnings.push('以裸 IP 直连（正规网站通常使用域名）');
  } else {
    warnings.push('以 IPv6 地址直连');
  }

  // 裸 IP 访问始终返回一条提示（低置信度），供用户参考
  return {
    is_threat: warnings.length > 1,
    source: '启发式检测',
    domain: ip,
    is_ip: true,
    threat_type: warnings.length > 1 ? '可疑 IP 访问' : 'IP 直连提示',
    warnings,
    description: warnings.join('；'),
    confidence: warnings.length > 1 ? 'medium' : 'low'
  };
}

// ---------- 启发式检测 ----------
function heuristicCheck(domain) {
  const warnings = [];

  // 检测1：域名包含知名品牌拼写变体 (typosquatting)
  const brandChecks = [
    { brand: 'google', patterns: ['googie', 'g00gle', 'go0gle', 'goggle', 'goog1e', 'googIe'] },
    { brand: 'paypal', patterns: ['paypaI', 'paypa1', 'paypai', 'paypaI', 'paypall', 'pay-pal'] },
    { brand: 'facebook', patterns: ['faceb00k', 'facebok', 'faceboook', 'face-book', 'fb'] },
    { brand: 'microsoft', patterns: ['micr0soft', 'micros0ft', 'mircosoft', 'micosoft'] },
    { brand: 'apple', patterns: ['appIe', 'app1e', 'aple', 'appie', 'appIe'] },
    { brand: 'amazon', patterns: ['arnazon', 'amaz0n', 'amazn', 'amazom'] },
    { brand: 'taobao', patterns: ['ta0bao', 'taoboa', 'taobao', 'taobaoo'] },
    { brand: 'alipay', patterns: ['aIipay', 'a1ipay', 'alipai', 'aIipay', 'alipayy'] },
    { brand: 'jd', patterns: ['ljd', 'jdl', 'j-d', 'jd-'] },
    { brand: 'qq', patterns: ['q-q'] },
  ];

  for (const { brand, patterns } of brandChecks) {
    for (const pattern of patterns) {
      if (domain.toLowerCase().includes(pattern.toLowerCase()) &&
          !domain.toLowerCase().includes(brand.toLowerCase())) {
        warnings.push(`疑似仿冒 ${brand}`);
        break;
      }
    }
  }

  // 检测2：超长域名 (DGA 特征)
  const baseDomain = domain.split('.')[0];
  if (baseDomain && baseDomain.length > 30) {
    warnings.push('异常长域名（可能是 DGA 生成）');
  }

  // 检测3：大量数字的域名
  const digitRatio = (baseDomain?.match(/\d/g) || []).length / (baseDomain?.length || 1);
  if (digitRatio > 0.5 && baseDomain?.length > 8) {
    warnings.push('域名含异常比例数字');
  }

  // 检测4：使用了常见的钓鱼 TLD
  const phishingTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.date'];
  for (const tld of phishingTLDs) {
    if (domain.toLowerCase().endsWith(tld)) {
      warnings.push(`可疑顶级域名 (${tld})`);
      break;
    }
  }

  // 检测5：包含连字符过多的域名
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    warnings.push('域名包含过多连字符');
  }

  if (warnings.length >= 2) {
    return {
      is_threat: true,
      source: '启发式检测',
      domain,
      threat_type: '可疑域名',
      warnings,
      description: warnings.join('；'),
      confidence: 'medium'
    };
  }

  return null;
}

// ---------- 描述生成 ----------
function buildDescription(threatTypes, blockedBy, urlCount) {
  const parts = [];

  if (threatTypes.size > 0) {
    const typeMap = {
      'malware_download': '恶意软件下载',
      'phishing': '钓鱼攻击',
      'botnet_cc': '僵尸网络 C&C',
      'malware': '恶意内容',
      'spam': '垃圾邮件',
      'scam': '诈骗',
      'trojan': '木马',
      'ransomware': '勒索软件',
      'exploit': '漏洞利用',
    };

    const typeDesc = [...threatTypes]
      .map(t => typeMap[t.toLowerCase()] || t)
      .join('、');
    parts.push(`检测到: ${typeDesc}`);
  }

  if (blockedBy.length > 0) {
    parts.push(`被 ${blockedBy.length} 个安全列表拦截`);
  }

  if (urlCount > 0) {
    parts.push(`关联 ${urlCount} 条恶意URL记录`);
  }

  return parts.join('；') || '检测到可疑活动';
}

// ---------- 公开 API ----------
/**
 * 查询域名的威胁情报
 * @param {string} domain - 域名
 * @returns {Object|null} - 威胁信息或 null（安全）
 */
export async function checkDomainThreat(domain) {
  // 按顺序查询各情报源
  for (const [key, source] of Object.entries(INTEL_SOURCES)) {
    if (!source.enabled) continue;

    try {
      const result = await source.check(domain);
      // is_threat===false 为信息性提示（如公网裸IP），不作为威胁上报，避免误报
      if (result && result.is_threat !== false) {
        console.log(`[威胁情报] ${source.name} 命中: ${domain}`, result);
        return result;
      }
    } catch (err) {
      console.error(`[威胁情报] ${source.name} 异常:`, err);
    }
  }

  return null; // 所有情报源都未命中 = 安全
}

/**
 * 全面检查主机（域名或IP），收集所有情报源的发现
 * 用于右键手动检查，无论安全与否都返回完整信息
 * 注意：自动跳过需要 API Key 但未配置的源
 * @param {string} host - 域名或 IP
 * @returns {Object} - { host, is_ip, is_threat, findings, primary, checked_at }
 */
export async function inspectHost(host) {
  const findings = [];

  for (const [key, source] of Object.entries(INTEL_SOURCES)) {
    if (!source.enabled) continue;

    // 需要 Key 但未配置的源，自动跳过
    if (key === 'phishtank' && !API_KEYS.phishtank) continue;

    try {
      const r = await source.check(host);
      if (r) findings.push(r);
    } catch (err) {
      console.error(`[威胁情报] ${source.name} 异常:`, err);
    }
  }

  const threats = findings.filter(f => f.is_threat === true);

  return {
    host,
    is_ip: isIP(host),
    is_threat: threats.length > 0,
    findings,                              // 所有发现（含信息性提示）
    primary: threats[0] || findings[0] || null,
    checked_at: Date.now()
  };
}

/**
 * 预加载块列表类情报源（扩展启动时调用）
 */
export async function preloadIntelligenceSources() {
  console.log('[威胁情报] 预加载情报源...');
  await Promise.allSettled([
    refreshPhishingArmyBlocklist()
  ]);
  console.log('[威胁情报] 预加载完成');
}

/**
 * 更新 API Key 配置
 * @param {Object} keys - { phishtank, alienvault, abuseipdb }
 */
export function updateAPIKeys(keys) {
  if (keys.phishtank !== undefined) API_KEYS.phishtank = keys.phishtank;
  if (keys.alienvault !== undefined) API_KEYS.alienvault = keys.alienvault;
  if (keys.abuseipdb !== undefined) API_KEYS.abuseipdb = keys.abuseipdb;

  // 有 Key 时自动启用对应源
  if (keys.phishtank) INTEL_SOURCES.phishtank.enabled = true;
  if (keys.abuseipdb) INTEL_SOURCES.abuseipdb.enabled = true;

  console.log('[威胁情报] API Key 已更新');
}

/**
 * 获取当前情报源状态
 */
export function getSourceStatus() {
  return Object.entries(INTEL_SOURCES).reduce((acc, [key, src]) => {
    acc[key] = {
      name: src.name,
      enabled: src.enabled && !(key === 'phishtank' && !API_KEYS.phishtank)
    };
    return acc;
  }, {});
}

/**
 * 获取缓存键名（用于持久化存储）
 */
export function getCacheKey(domain) {
  return `ti_cache_${domain}`;
}
