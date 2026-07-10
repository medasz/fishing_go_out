// ============================================================
//  威胁情报查询模块
//  支持多个情报源，自动降级
// ============================================================

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

  // 本地启发式检测 (备用)
  heuristic: {
    name: '启发式检测',
    enabled: true,
    check: async (domain) => {
      return heuristicCheck(domain);
    }
  }
};

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
      if (result) {
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
 * 获取缓存键名（用于持久化存储）
 */
export function getCacheKey(domain) {
  return `ti_cache_${domain}`;
}
