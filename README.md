# 钓鱼拦截 - Chrome 浏览器威胁情报扩展

实时检测访问网站的威胁情报，当访问钓鱼/恶意域名或 IP 时**在页面加载前全屏阻断**，不给恶意网站下发任何流量。支持自动拦截与右键手动检查。

## 功能特性

- **导航前拦截**：基于 `onBeforeNavigate`，在浏览器建立连接前即阻断，**恶意网站 0 流量下发**
- **全屏阻断页**：命中威胁时重定向到扩展内置全屏警告页面（非页面内横幅，不含任何外部资源）
- **右键菜单检查**：选中域名/IP 或链接，右键即可手动查询威胁情报
- **多情报源聚合**（5 个实时 API 源 + 1 个本地引擎，免 Key 或免费 Key）：
  - **实时 API 类**：URLhaus (abuse.ch)、AlienVault OTX、PhishTank（需免费 App Key）、**VirusTotal（多引擎扫描，需免费 API Key）**、**微步 ThreatBook（国内威胁情报，需免费 API Key）**
  - **本地启发式检测** — 品牌仿冒、DGA 域名、可疑 TLD、裸 IP 风险等
- **检查结果弹窗**：右键检查结果以浮层形式展示，聚合所有情报源发现，支持查看原始数据
- **桌面通知**：通过 Chrome 通知系统实时告警
- **扩展徽章**：工具栏图标显示当前页面安全状态
- **检测统计**：Popup 弹窗展示累计检测数据与当前页状态
- **智能缓存**：域名/威胁查询结果 30 分钟缓存，减少重复请求
- **手动放行白名单**：用户确认继续访问后域名记入会话级别白名单，不再二次拦截

## 项目结构

```
fishing_go_out/
├── manifest.json          # 扩展配置文件 (Manifest V3)
├── background.js          # 后台 Service Worker（导航拦截 + 阻断页重定向 + 右键菜单 + 情报查询）
├── content.js             # 内容脚本（右键检查结果弹窗）
├── blocked.html           # 全屏阻断告警页面
├── blocked.js             # 阻断页交互逻辑（继续访问 / 返回安全页面）
├── popup.html             # 弹出窗口页面
├── popup.js               # 弹出窗口脚本
├── utils/
│   └── threat-intel.js    # 威胁情报查询模块（多源聚合 + IP 检测 + 块列表缓存）
├── styles/
│   ├── warning.css        # 检查结果弹窗样式
│   └── popup.css          # 弹出窗口样式
└── images/
    ├── icon16.png         # 扩展图标 16x16
    ├── icon48.png         # 扩展图标 48x48
    └── icon128.png        # 扩展图标 128x128
```

## 安装方法

1. 打开 Chrome 浏览器，地址栏输入 `chrome://extensions/`
2. 打开右上角 **开发者模式** 开关
3. 点击左上角 **加载已解压的扩展程序**
4. 选择 `fishing_go_out` 文件夹
5. 扩展安装完成，工具栏会出现盾牌图标

## 使用方式

### 自动拦截
安装后无需任何操作，每次访问网站时自动查询域名威胁情报。命中威胁时会在**页面加载前**跳转到扩展内置的全屏阻断页，目标网站不会收到任何网络请求。

### 右键手动检查
在网页上右键，可使用以下菜单项：

| 右键位置 | 菜单项 | 说明 |
|---------|--------|------|
| 链接 | 检查此链接的威胁情报 | 提取链接中的域名/IP 并查询 |
| 选中文本 | 检查选中的域名/IP | 智能提取选中文本中的域名或 IP |
| 图片 | 检查图片来源的威胁情报 | 提取图片 src 中的域名 |
| 页面空白处 | 检查当前页面的威胁情报 | 查询当前页面域名 |

查询后会在页面右上角弹出结果浮层，展示所有情报源的发现，支持：
- 点击 **在 URLhaus 查看** 跳转外部详情
- 点击 **原始数据** 查看完整 JSON 响应
- 安全结果 8 秒后自动关闭，威胁结果需手动关闭

### 查看状态
点击工具栏盾牌图标，查看当前页面安全状态、累计检测统计。在「情报源」区域可逐项勾选启用/停用各检测源（含本地启发式检测），开关会持久化保存，下次打开自动生效，无需重新填写 API Key。

### 配置 API Key
点击工具栏盾牌图标 → 展开 **⚙️ 高级设置 / API Key**，在弹窗中输入并保存你的免费 Key 即可解锁对应情报源（也可直接在 `utils/threat-intel.js` 顶部的 `API_KEYS` 对象中填写）：

- **VirusTotal**（推荐）：在 [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) 免费申请，提供 70+ 安全引擎的多引擎判定，作为拦截的确认层
- **微步 ThreatBook**：在 [x.threatbook.com](https://x.threatbook.com/) 免费申请，国内威胁情报平台，提供域名/IP 的多维威胁判定（钓鱼、C2、恶意软件等），作为拦截的确认层
- **PhishTank**：在 [phishtank.com/register.php](https://www.phishtank.com/register.php) 申请 App Key
- **AlienVault OTX**：留空使用公开 API，[注册](https://otx.alienvault.com/) 后可获得更高配额

保存后对应情报源自动启用，Popup 面板可看到状态变化。

### 告警处理（全屏阻断页）
当访问被拦截时，浏览器会展示扩展内置的全屏阻断页，**不会加载目标网站的任何资源**：

- **「返回安全页面」**：回退到上一页或关闭当前标签页
- **「我了解风险，继续访问」**：域名加入会话白名单 → 跳转到原始 URL，当前会话内不再拦截此域名

### 安全工作原理

```
用户点击恶意链接
  → onBeforeNavigate 触发（TCP 连接尚未建立）
  → 查询威胁情报（缓存优先，多源聚合）
  → 命中威胁 → tabs.update() 重定向到 chrome-extension://blocked.html
  → 目标网站 0 字节流量，无 JS 执行，无信息泄露风险
```

阻断页由扩展自身托管（`chrome-extension://` 协议），100% 离线，不依赖任何外部资源。

## 威胁情报源

### URLhaus (abuse.ch)
- 由瑞士 abuse.ch 运营的非营利威胁情报平台
- 收集全球恶意软件分发 URL
- 免费使用，无需 API Key
- 查询端点: `https://urlhaus-api.abuse.ch/v1/host/`

### PhishTank
- OpenDNS 社区驱动的钓鱼 URL 验证平台
- 支持社区投票验证，结果区分"已验证/待验证"
- 免费使用，需申请 [开发者 App Key](https://www.phishtank.com/register.php)
- 查询端点: `https://checkurl.phishtank.com/checkurl/`

### AlienVault OTX
- 全球最大的开源威胁情报社区
- 聚合数千条安全研究员的威胁脉冲 (Pulses)
- 公开 API 免 Key 即可使用（有速率限制），也可[免费注册](https://otx.alienvault.com/)获取更多配额
- 查询端点: `https://otx.alienvault.com/api/v1/indicators/`

### VirusTotal（推荐，需免费 API Key）
- 全球最大的多引擎聚合扫描平台，调用 70+ 安全厂商引擎对域名/IP 联合判定
- 免费 API Key 申请: [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- 查询端点:
  - 域名: `https://www.virustotal.com/api/v3/domains/{domain}`
  - IP: `https://www.virustotal.com/api/v3/ip_addresses/{ip}`
- 判定逻辑：当恶意引擎数 ≥ 3 个（经本地阈值 `VT_MALICIOUS_THRESHOLD` 可调），或信誉评分 `reputation ≤ -10` 时判定为威胁，并提取检出引擎清单
- 定位为**确认层**：在情报源列表中排最后，仅当其他源均未命中时才触发，以节省免费配额
- 免费配额限制：约 **4 次/分钟、500 次/天**，触发 429 速率限制时自动跳过（不影响其他源拦截）

### 微步 ThreatBook（需免费 API Key）
- 国内领先的威胁情报平台，覆盖钓鱼、恶意软件、C2、僵尸网络、欺诈等场景
- 免费 API Key 申请: [x.threatbook.com](https://x.threatbook.com/)（需注意调用前需将出口 IP 加入白名单）
- 查询端点:
  - 域名: `https://api.threatbook.cn/v3/domain/query`
  - IP: `https://api.threatbook.cn/v3/scene/ip_reputation`
- 判定逻辑：域名命中 ThreatBook 威胁标签（Phishing / Malware / C2 / Botnet / Fraud 等）即判定为威胁；IP 则以 `is_malicious` 或威胁标签判定，并提取 `severity` / `confidence_level` 作为置信度
- 定位为**确认层**：在情报源列表中排最后（启发式前），仅当其他源均未命中时才触发，以节省免费配额
- 免费配额限制：按积分/次计费，触发配额耗尽时 `response_code` 非 0，自动跳过（不影响其他源拦截）

### 本地启发式检测
- 知名品牌仿冒域名检测 (typosquatting)
- DGA 生成域名识别（高熵值、随机字符特征）
- 可疑顶级域名检测 (`.tk`, `.ml`, `.xyz`, `.top` 等)
- **裸 IP 访问检测**：直接以 IP 访问网站是钓鱼常见特征
- **内网/保留 IP 识别**：识别 localhost、私有网段等非公开地址

### 数据源选型说明
本扩展**仅采用实时 API 查询类情报源**（URLhaus / PhishTank / AlienVault OTX / VirusTotal / 微步 ThreatBook）与本地启发式引擎，不下载/缓存本地块列表文件。此前曾接入的块列表类源（Phishing Army、Phishing.Database、CERT Polska、CyberCrime-Tracker、CINS Army、ET Compromised、GreenSnow、Honeynet Asia）因依赖下载文本/CSV 文件并在本地匹配，与"导航前实时查询、零本地文件依赖"的设计目标不符，已移除。以下类型因不适用于实时 URL 拦截（需文件哈希/漏洞库/匿名网络识别/额外聚合层）也未采用：

- **文件哈希类**：Malshare、CCAM SHA1 列表（浏览器导航只看到域名/IP，无文件可校验）
- **CVE 漏洞类**：eCrimeLabs Metasploit CVE（面向资产漏洞优先级，非 URL 拦截）
- **Tor 出口节点**：dan.me.uk torlist（仅标识匿名流量，非攻击指标，全量封禁误伤高）
- **扫描信号类**：Dataplane.org（研究级网络信号，需结合上下文，非黑名单）
- **MISP JSON 聚合源**：CIRCL、Botvrij.eu（需额外解析/聚合层，后续可扩展）

## 注意事项

- 首次访问某域名时会发起 API 请求，可能稍慢（`onBeforeNavigate` 中异步查询）
- 安全域名会缓存 30 分钟，避免重复查询
- 右键手动检查不读缓存，始终实时查询
- 用户放行的域名仅在当前浏览器会话中有效，重启浏览器后白名单自动清空
- URLhaus API 有限速，请勿短时间内大量查询
- **VirusTotal 免费 Key 限速约 4 次/分钟、500 次/天**，仅作为确认层参与拦截；高频浏览可能触发 429 限制，此时自动跳过 VT 查询，不影响其他源的拦截能力
- **微步 ThreatBook** 需将调用方出口 IP 加入白名单（x.threatbook.com 控制台配置），并按积分配额计费；配额耗尽时 `response_code` 非 0，自动跳过查询，不影响其他源的拦截能力
- **代理场景特别注意**：扩展的请求会跟随浏览器代理。开代理后微步看到的出口 IP 是**代理服务器 IP**，白名单应填**代理出口 IP**（而非本机 IP）；若代理出口 IP 动态变化（住宅/动态出口），白名单机制无法生效，可暂不启用微步，或开启「微步查询直连代理」开关（见上）
- 建议搭配广告拦截器使用更佳
