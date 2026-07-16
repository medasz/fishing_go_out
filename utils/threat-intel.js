// ============================================================
//  威胁情报查询模块
//  支持多个情报源，自动降级
// ============================================================

// ---------- 情报源 API Key 配置 ----------
// 可选：填入你在对应平台申请的免费 API Key 以启用相关情报源
const API_KEYS = {
  alienvault: '',  // 申请地址: https://otx.alienvault.com/ (留空则使用公开 API)
  abuseipdb: '',   // 申请地址: https://www.abuseipdb.com/ (仅 IP 查询)
  virustotal: '',  // 申请地址: https://www.virustotal.com/gui/my-apikey (免费 Key，多引擎扫描)
  threatbook: '',  // 申请地址: https://x.threatbook.com/ (国内威胁情报，需免费 API Key)
  pulsedive: '',   // 申请地址: https://pulsedive.com/account (免费 API Key)
  urlhaus: ''      // 申请地址: https://auth.abuse.ch/ (免费 Auth-Key，URLhaus 查询必填，否则返回 401)
};

// ---------- VirusTotal 配置 ----------
// 恶意引擎数达到该阈值即判定为威胁（免费 Key 限速 4 次/分钟，故作为确认层置于最后）
const VT_MALICIOUS_THRESHOLD = 3;
const VT_TIMEOUT = 12000;

// ---------- 微步 ThreatBook 配置 ----------
const TB_TIMEOUT = 12000;

// 微步威胁判定类型（命中即视为威胁）
const TB_MALICIOUS_JUDGMENTS = new Set([
  'Phishing', 'Malware', 'C2', 'Botnet', 'Fraud', 'Scam',
  'Ransomware', 'Trojan', 'Backdoor', 'Exploit', 'Mining', 'Gambling'
]);

// 微步 tags_classes 中的攻击手法标签，命中即视为威胁
const TB_MALICIOUS_TAGS = new Set([
  '仿冒', '仿冒软件下载站', '仿冒网站', '钓鱼', '钓鱼网站', '恶意软件', 'Malware',
  'C2', '远控', '远控 C2', '木马', 'Trojan', '勒索', 'Ransomware',
  '挖矿', 'Mining', 'CoinMiner', 'MiningPool', '矿池',
  '僵尸网络', 'Botnet', '后门', 'Backdoor', 'APT', '蠕虫', '病毒',
  '窃密', '信息窃取', '间谍软件', '供应链攻击', '水坑攻击',
  '欺诈', '诈骗', 'Scam', 'Fraud', '垃圾邮件', 'Spam',
  '漏洞利用', 'Exploit', '扫描', 'Scanner', '暴力破解', 'Brute Force',
  '代理', 'Proxy', 'VPN', '僵尸', 'Zombie'
]);

function extractThreatBookTags(info) {
  const tags = [];
  const tcs = info.tags_classes || [];
  for (const tc of tcs) {
    if (typeof tc === 'string') {
      tags.push(tc);
    } else if (tc && typeof tc === 'object') {
      if (Array.isArray(tc.tags)) tags.push(...tc.tags);
      if (typeof tc.name === 'string') tags.push(tc.name);
      if (typeof tc.tags_type === 'string') tags.push(tc.tags_type);
    }
  }
  return tags;
}

const TB_JUDGMENT_MAP = {
  Phishing: '钓鱼网站', Malware: '恶意软件', C2: '远控 C2', Botnet: '僵尸网络',
  Fraud: '欺诈', Scam: '诈骗', Spam: '垃圾邮件', Suspicious: '可疑',
  Exploit: '漏洞利用', Ransomware: '勒索软件', Trojan: '木马', Backdoor: '后门',
  Mining: '挖矿', Gambling: '赌博', DDoS: 'DDoS', Scanner: '扫描',
  'Brute Force': '暴力破解', Zombie: '傀儡机', Proxy: '代理', VPN: 'VPN'
};

// ---------- 微步 ThreatBook 通用查询与解析 ----------
async function queryThreatBookEndpoint(host, endpoint, isIpHost, key) {
  const url = `https://api.threatbook.cn/v3/${endpoint}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TB_TIMEOUT);

  try {
    const body = new URLSearchParams({ apikey: key, resource: host, lang: 'zh' });
    if (isIpHost) body.set('realtime_verdict', 'true');

    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();

    // response_code 非 0 表示错误：如 Key 无效、配额耗尽、无接口权限
    if (data.response_code !== 0) {
      console.warn(`[ThreatBook] ${endpoint} 查询失败 (code=${data.response_code}): ${data.verbose_msg}`);
      return { data: null, noPermission: true, code: data.response_code, msg: data.verbose_msg };
    }

    return { data, noPermission: false };
  } catch (err) {
    console.warn(`[ThreatBook] ${endpoint} 查询失败: ${err.message}`);
    return { data: null, noPermission: false, error: err.message };
  }
}

function parseThreatBookResponse(data, host, isIpHost) {
  if (!data) return null;
  const info = isIpHost ? data.ips?.[host] : data.domains?.[host];
  if (!info) return null;

  const judgments = (info.judgments || []).filter(j => TB_MALICIOUS_JUDGMENTS.has(j));
  const tags = extractThreatBookTags(info);
  const maliciousTags = tags.filter(t => TB_MALICIOUS_TAGS.has(t));
  const isMalicious = info.is_malicious === true || judgments.length > 0 || maliciousTags.length > 0;
  if (!isMalicious) return null;


  // 优先使用 judgments 作为威胁理由；没有 judgments 时使用攻击手法标签
  const reasons = judgments.length > 0
    ? judgments.map(j => TB_JUDGMENT_MAP[j] || j)
    : [...new Set(maliciousTags)];

  const strongByJudgment = judgments.some(j =>
    ['Phishing', 'Malware', 'C2', 'Botnet', 'Ransomware', 'Trojan', 'Backdoor', 'Fraud', 'Scam'].includes(j));
  const strongByTag = maliciousTags.some(t =>
    ['仿冒软件下载站', '钓鱼', '钓鱼网站', '恶意软件', 'C2', '远控', '木马', '勒索', '挖矿', '僵尸网络', '后门', 'APT', '窃密', '欺诈', '诈骗'].includes(t) ||
    ['Phishing', 'Malware', 'C2', 'Botnet', 'Ransomware', 'Trojan', 'Backdoor', 'Fraud', 'Scam'].includes(t));

  return {
    is_threat: true,
    source: '微步 ThreatBook',
    domain: host,
    threat_type: reasons.join('、') || (isIpHost ? '可疑 IP' : '可疑域名'),
    judgments: judgments.length ? judgments : (info.judgments || []),
    tags: maliciousTags,
    confidence_level: info.confidence_level || info.confidence || null,
    severity: info.severity || null,
    permalink: info.permalink || null,
    description: `微步情报命中威胁类型: ${reasons.join('、')}`,
    confidence: strongByJudgment || strongByTag ||
      info.confidence_level === 'high' || info.confidence === 'high' ||
      info.severity === 'critical' || info.severity === 'high' ? 'high' : 'medium'
  };
}

// ---------- 以下情报源均为实时 API 查询，不下载本地块列表文件 ----------

// ---------- 情报源配置 ----------
const INTEL_SOURCES = {
  // URLhaus - 恶意软件分发 URL 数据库 (免费，但自 2024 年起查询必须携带 Auth-Key)
  urlhaus: {
    name: 'URLhaus',
    endpoint: 'https://urlhaus-api.abuse.ch/v1/host/',
    enabled: true,
    requiresKey: true,        // 未配置 Auth-Key 时自动跳过，避免无谓的 401 报错
    keyName: 'urlhaus',
    timeout: 10000,
    check: async (domain) => {
      const key = API_KEYS.urlhaus;
      if (!key) return null;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10000);

      try {
        const resp = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Auth-Key': key
          },
          body: new URLSearchParams({ host: domain }),
          signal: controller.signal
        });
        clearTimeout(timer);

        // 401 = Auth-Key 缺失/无效，明确提示并跳过，不再当作未知错误抛出
        if (resp.status === 401) {
          console.warn('[URLhaus] Auth-Key 缺失或无效 (401)，请在设置中填写免费 Auth-Key');
          return null;
        }
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

  // VirusTotal — 多引擎聚合扫描平台 (免费 API Key，限速 4 次/分钟，作为确认层)
  virustotal: {
    name: 'VirusTotal',
    enabled: true,
    requiresKey: true,
    keyName: 'virustotal',
    timeout: VT_TIMEOUT,
    check: async (host) => {
      const key = API_KEYS.virustotal;
      if (!key) return null;

      const endpoint = isIP(host) ? 'ip_addresses' : 'domains';
      const url = `https://www.virustotal.com/api/v3/${endpoint}/${encodeURIComponent(host)}`;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), VT_TIMEOUT);

      try {
        const resp = await fetch(url, {
          headers: { 'x-apikey': key },
          signal: controller.signal
        });
        clearTimeout(timer);

        if (resp.status === 401) {
          console.warn('[VirusTotal] API Key 无效 (401)');
          return null;
        }
        if (resp.status === 429) {
          console.warn('[VirusTotal] 触发速率限制 (429)，本次跳过查询');
          return null;
        }
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        if (resp.status === 404) return null; // 无此指标记录

        const data = await resp.json();
        const attrs = data?.data?.attributes;
        if (!attrs) return null;

        const stats = attrs.last_analysis_stats || {};
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const reputation = typeof attrs.reputation === 'number' ? attrs.reputation : 0;
        const categories = Object.keys(attrs.categories || {});

        // 判定：恶意引擎数达阈值，或信誉评分极低
        if (malicious >= VT_MALICIOUS_THRESHOLD || reputation <= -10) {
          const detections = [];
          const results = attrs.last_analysis_results || {};
          for (const [engine, r] of Object.entries(results)) {
            if (r && (r.category === 'malicious' || r.category === 'suspicious')) {
              detections.push(engine);
            }
          }

          const total =
            (stats.harmless || 0) + malicious + suspicious +
            (stats.undetected || 0) + (stats.timeout || 0);

          return {
            is_threat: true,
            source: 'VirusTotal',
            domain: host,
            threat_type: categories.length ? categories.join(', ') : '恶意活动',
            malicious_count: malicious,
            suspicious_count: suspicious,
            total_engines: total,
            reputation,
            detections: detections.slice(0, 12),
            description: `VirusTotal ${malicious} 个安全引擎判定为恶意` +
              (reputation < 0 ? `，信誉评分 ${reputation}` : '') +
              (detections.length ? `（${detections.slice(0, 5).join('、')} 等）` : ''),
            confidence: malicious >= 5 ? 'high' : 'medium'
          };
        }
        return null;
      } catch (err) {
        console.warn(`[VirusTotal] 查询失败: ${err.message}`);
        return null;
      }
    }
  },

  // 微步在线 ThreatBook — 国内威胁情报平台 (需免费 API Key；默认关闭，可在弹窗开关启用)
  threatbook: {
    name: '微步 ThreatBook',
    enabled: false,
    requiresKey: true,
    keyName: 'threatbook',
    timeout: TB_TIMEOUT,
    check: async (host) => {
      const key = API_KEYS.threatbook;
      if (!key) {
        console.log('[ThreatBook] 未配置 API Key，跳过');
        return null;
      }
      if (!INTEL_SOURCES.threatbook.enabled) {
        console.log('[ThreatBook] 情报源未启用，跳过');
        return null;
      }

      const isIpHost = isIP(host);
      console.log(`[ThreatBook] 开始查询 ${host} (类型: ${isIpHost ? 'IP' : '域名'})`);

      // 1. 尝试专用接口：IP 用 ip_reputation，域名用 domain/query
      const primaryEndpoint = isIpHost ? 'scene/ip_reputation' : 'domain/query';
      const primary = await queryThreatBookEndpoint(host, primaryEndpoint, isIpHost, key);

      // 专用接口成功返回数据 → 解析并命中则直接返回
      if (primary && primary.data && !primary.noPermission) {
        const result = parseThreatBookResponse(primary.data, host, isIpHost);
        if (result) {
          console.log(`[ThreatBook] ${primaryEndpoint} 命中威胁:`, result);
          return result;
        }
        console.log(`[ThreatBook] ${primaryEndpoint} 返回数据但未命中威胁`);
      }

      // 2. 专用接口无权限、网络失败、未返回该主机数据 → 降级到 scene/dns
      //    免费 Key 通常有 scene/dns 权限，且 tags_classes 包含仿冒/攻击标签
      const primaryInfo = primary.data && (isIpHost ? primary.data.ips?.[host] : primary.data.domains?.[host]);
      if (!primary || primary.noPermission || primary.error || !primary.data || !primaryInfo) {
        console.log(`[ThreatBook] ${primaryEndpoint} 未命中/无权限/无数据，降级到 scene/dns`);
        const fallback = await queryThreatBookEndpoint(host, 'scene/dns', isIpHost, key);
        if (fallback && fallback.data && !fallback.noPermission) {
          const result = parseThreatBookResponse(fallback.data, host, isIpHost);
          if (result) {
            console.log('[ThreatBook] scene/dns 命中威胁:', result);
            return result;
          }
        }
      }

      console.log(`[ThreatBook] ${host} 未命中威胁`);
      return null;
    }

  },

  // Pulsedive — 综合威胁情报平台 (免费 API Key，支持域名/IP/URL)
  pulsedive: {
    name: 'Pulsedive',
    endpoint: 'https://pulsedive.com/api/indicator.php',
    enabled: true,
    requiresKey: true,
    keyName: 'pulsedive',
    timeout: 12000,
    check: async (host) => {
      const key = API_KEYS.pulsedive;
      if (!key) return null;

      // 构造查询 URL：indicator 可为域名或 IP，key 可选但建议带上以提高限额
      const url = new URL('https://pulsedive.com/api/indicator.php');
      url.searchParams.set('indicator', host);
      url.searchParams.set('pretty', '0');
      url.searchParams.set('key', key);

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);

      try {
        const resp = await fetch(url, { signal: controller.signal });
        clearTimeout(timer);

        if (resp.status === 401) {
          console.warn('[Pulsedive] API Key 无效 (401)');
          return null;
        }
        if (resp.status === 404) return null; // 指标库中无记录
        if (resp.status === 429) {
          console.warn('[Pulsedive] 触发速率限制 (429)，本次跳过查询');
          return null;
        }
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const data = await resp.json();
        if (data.error) return null;

        // 判定标准：
        // 1) 综合风险等级为 high / critical
        // 2) 任一关联威胁的 category 命中攻击手法（钓鱼/恶意软件/C2/诈骗等）
        // 3) 任一关联威胁自身风险为 high / critical
        const THREAT_RISKS = new Set(['high', 'critical']);
        const risk = (data.risk || '').toLowerCase();

        const threats = Array.isArray(data.threats) ? data.threats : [];
        const threatCats = threats.map(t => (t.category || '').toLowerCase());
        const catHit = threatCats.some(c =>
          /phish|malware|c2|botnet|scam|fraud|ransom|trojan|backdoor|exploit|mining|spam/.test(c));
        const highThreat = threats.some(t => THREAT_RISKS.has((t.risk || '').toLowerCase()));

        if (THREAT_RISKS.has(risk) || catHit || highThreat) {
          const names = threats.map(t => t.name).filter(Boolean);
          const catLabels = [...new Set(threatCats)].filter(Boolean);
          // 威胁类型优先级：钓鱼 > 恶意软件 > 其他
          let threatType = '恶意活动';
          if (catLabels.some(c => /phish/.test(c))) threatType = '钓鱼网站';
          else if (catLabels.some(c => /malware/.test(c))) threatType = '恶意软件';
          else if (catLabels.length) threatType = catLabels.join(', ');

          return {
            is_threat: true,
            source: 'Pulsedive',
            domain: host,
            threat_type: threatType,
            risk,
            threats: names,
            feeds: (Array.isArray(data.feeds) ? data.feeds : []).map(f => f.name).filter(Boolean),
            description: `Pulsedive 风险等级 "${data.risk || 'unknown'}"` +
              (names.length ? `，关联威胁: ${names.slice(0, 5).join('、')}` : '') +
              (catLabels.length ? `（分类: ${catLabels.join('、')}）` : ''),
            confidence: risk === 'critical' ? 'high' : 'medium'
          };
        }
        return null;
      } catch (err) {
        console.warn(`[Pulsedive] 查询失败: ${err.message}`);
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
  for (const [, source] of Object.entries(INTEL_SOURCES)) {
    if (!source.enabled) {
      console.log(`[威胁情报] ${source.name} 未启用，跳过`);
      continue;
    }
    if (source.requiresKey && !API_KEYS[source.keyName]) {
      console.log(`[威胁情报] ${source.name} 需要 API Key 但未配置，跳过`);
      continue;
    }

    try {
      console.log(`[威胁情报] 开始查询 ${source.name}: ${domain}`);
      const result = await source.check(domain);
      // is_threat===false 为信息性提示（如公网裸IP），不作为威胁上报，避免误报
      if (result && result.is_threat !== false) {
        console.log(`[威胁情报] ${source.name} 命中: ${domain}`, result);
        return result;
      }
      if (result) {
        console.log(`[威胁情报] ${source.name} 返回信息性结果: ${domain}`, result);
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

  for (const [, source] of Object.entries(INTEL_SOURCES)) {
    if (!source.enabled) {
      console.log(`[威胁情报] ${source.name} 未启用，跳过`);
      continue;
    }

    // 需要 Key 但未配置的源，自动跳过
    if (source.requiresKey && !API_KEYS[source.keyName]) {
      console.log(`[威胁情报] ${source.name} 需要 API Key 但未配置，跳过`);
      continue;
    }

    try {
      console.log(`[威胁情报] 手动检查开始查询 ${source.name}: ${host}`);
      const r = await source.check(host);
      if (r) {
        findings.push(r);
        console.log(`[威胁情报] ${source.name} 返回:`, r);
      } else {
        console.log(`[威胁情报] ${source.name} 未命中`);
      }
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
 * 预加载情报源（扩展启动时调用）
 * 当前所有情报源均为实时 API 查询，无需预下载块列表
 */
export async function preloadIntelligenceSources() {
  console.log('[威胁情报] 情报源均为实时 API 查询，无需预加载块列表');
}

/**
 * 更新 API Key 配置
 * @param {Object} keys - { alienvault, abuseipdb, virustotal, threatbook, pulsedive }
 */
export function updateAPIKeys(keys) {
  if (keys.alienvault !== undefined) API_KEYS.alienvault = keys.alienvault;
  if (keys.abuseipdb !== undefined) API_KEYS.abuseipdb = keys.abuseipdb;
  if (keys.virustotal !== undefined) API_KEYS.virustotal = keys.virustotal;
  if (keys.threatbook !== undefined) API_KEYS.threatbook = keys.threatbook;
  if (keys.pulsedive !== undefined) API_KEYS.pulsedive = keys.pulsedive;
  if (keys.urlhaus !== undefined) API_KEYS.urlhaus = keys.urlhaus;
  // 注意：源的启用/禁用由用户的情报源开关(sourceEnabled)控制，不再随 Key 自动启用
  console.log('[威胁情报] API Key 已更新');
}

/**
 * 应用用户自定义的情报源开关
 * @param {Object} toggles - { sourceKey: boolean }
 */
export function applySourceToggles(toggles) {
  if (!toggles) return;
  for (const [key, val] of Object.entries(toggles)) {
    if (INTEL_SOURCES[key]) INTEL_SOURCES[key].enabled = !!val;
  }
  console.log('[威胁情报] 情报源开关已应用');
}

/**
 * 获取当前情报源状态
 */
export function getSourceStatus() {
  return Object.entries(INTEL_SOURCES).reduce((acc, [key, src]) => {
    const hasKey = !src.requiresKey || !!API_KEYS[src.keyName];
    acc[key] = {
      name: src.name,
      userEnabled: src.enabled,            // 用户开关状态
      enabled: src.enabled && hasKey,      // 实际是否生效（还需 Key）
      requiresKey: !!src.requiresKey,
      hasKey
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
