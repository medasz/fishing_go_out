# 钓鱼拦截 - Chrome 浏览器威胁情报扩展

实时检测访问网站的威胁情报，当访问钓鱼/恶意域名或 IP 时弹出告警。支持自动检测与右键手动检查。

## 功能特性

- **实时域名/IP 检测**：每次网页导航时自动查询威胁情报
- **右键菜单检查**：选中域名/IP 或链接，右键即可手动查询威胁情报
- **多情报源聚合**（4 个开源源 + 1 个本地引擎）：
  - **URLhaus** (abuse.ch) — 全球恶意软件分发 URL 数据库
  - **Phishing Army** — 开源钓鱼域名块列表（本地匹配，极速）
  - **PhishTank** — 社区驱动的钓鱼 URL 数据库（需免费 App Key）
  - **AlienVault OTX** — 全球最大开源威胁情报社区
  - **本地启发式检测** — 品牌仿冒、DGA 域名、可疑 TLD、裸 IP 风险等
- **页面内告警横幅**：检测到威胁时在当前页面顶部显示红色告警（可关闭/可返回）
- **检查结果弹窗**：右键检查结果以浮层形式展示，聚合所有情报源发现，支持查看原始数据
- **桌面通知**：通过 Chrome 通知系统实时告警
- **扩展徽章**：工具栏图标显示当前页面安全状态
- **检测统计**：Popup 弹窗展示累计检测数据与当前页状态
- **智能缓存**：30 分钟内存缓存 + storage 持久化，减少 API 请求

## 项目结构

```
fishing_go_out/
├── manifest.json          # 扩展配置文件 (Manifest V3)
├── background.js          # 后台 Service Worker（导航监听 + 右键菜单 + 情报查询）
├── content.js             # 内容脚本（告警横幅 + 检查结果弹窗）
├── popup.html             # 弹出窗口页面
├── popup.js               # 弹出窗口脚本
├── utils/
│   └── threat-intel.js    # 威胁情报查询模块（URLhaus + 启发式 + IP 检测）
├── styles/
│   ├── warning.css        # 告警横幅 + 检查结果弹窗样式
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

### 自动检测
安装后无需任何操作，每次访问网站时自动查询域名威胁情报。

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
点击工具栏盾牌图标，查看当前页面安全状态、累计检测统计，以及各情报源的启用状态。

### 配置 API Key
在 `utils/threat-intel.js` 顶部的 `API_KEYS` 对象中填入你的免费 Key 以解锁更多情报源：

```javascript
const API_KEYS = {
  phishtank: '',   // 申请: https://www.phishtank.com/register.php
  alienvault: '',  // 申请: https://otx.alienvault.com/ (留空使用公开 API)
};
```

填入后对应的情报源会自动启用，在 Popup 面板可看到状态变化。

### 告警处理
- **「我了解风险，继续访问」**：关闭告警横幅，继续浏览
- **「返回安全页面」**：回退到上一页

## 威胁情报源

### URLhaus (abuse.ch)
- 由瑞士 abuse.ch 运营的非营利威胁情报平台
- 收集全球恶意软件分发 URL
- 免费使用，无需 API Key
- 查询端点: `https://urlhaus-api.abuse.ch/v1/host/`

### Phishing Army
- 开源钓鱼域名块列表，定期更新
- 本地匹配，查询速度极快
- 完全免费，无需 API Key
- 下载地址: `https://phishing.army/download/phishing_army_blocklist.txt`

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

### 本地启发式检测
- 知名品牌仿冒域名检测 (typosquatting)
- DGA 生成域名识别（高熵值、随机字符特征）
- 可疑顶级域名检测 (`.tk`, `.ml`, `.xyz`, `.top` 等)
- **裸 IP 访问检测**：直接以 IP 访问网站是钓鱼常见特征
- **内网/保留 IP 识别**：识别 localhost、私有网段等非公开地址

## 注意事项

- 首次访问某域名时会发起 API 请求，可能稍慢
- 安全域名会缓存 30 分钟，避免重复查询
- 右键手动检查不读缓存，始终实时查询
- URLhaus API 有限速，请勿短时间内大量查询
- 建议搭配广告拦截器使用更佳
