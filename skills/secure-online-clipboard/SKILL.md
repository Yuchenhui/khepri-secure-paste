---
name: secure-online-clipboard
description: 用 Secure online clipboard 服务端到端加密上传内容并取回链接。当需要把文本或小文件（≤512 KB）生成一个加密粘贴链接、或同时要长链和短码时使用。覆盖 ttl 有效期、阅后即焚、阅读次数限制、IP 锁定、短码长度、可选密码等全部参数，附零依赖 Node 参考实现与字段契约。
---

# Secure online clipboard 编程上传

目标：让 Agent 不经过浏览器，直接把内容加密上传到 Secure online clipboard，拿到 `?id#key` 长链，并按需再拿一个短码。

**加密在本地完成，服务器只存密文。** 密钥在 URL 的 fragment（`#` 后面），不会随请求发送——所以 Agent 必须自己生成密钥并自己加密，不能只调一个「上传文本」的接口。

**上传和下载完全对称。** `--file` 传上去的文件，读回来是同名同字节的文件；纯文本传上去，读回来就是文本。两种粘贴用同一个标记区分，读取端自动识别。

## 1. 端点与约束

| 端点 | 方法 | 用途 | 备注 |
|---|---|---|---|
| `/api/paste` | POST | 创建粘贴 | 无 Origin 校验，CLI 可直接调 |
| `/api/paste/<id>` | GET | 取 salt / iterations / claim（不含密文） | 阅读页第一步 |
| `/api/paste/<id>` | POST | 提交 proof 取密文 | body ≤256 B |
| `/s/shorten` | POST | 长链换短码 | 无 Origin 也放行；错误 Origin 仍 403 |

生产环境 nginx 把 `/s/` 代理到短链服务，所以调用方统一打 `https://paste.vantolab.com/s/shorten`，不需要知道短链服务的真实端口。

**自己搭本地环境时例外**：如果直接跑 `node src/core.js` 而没有 nginx，`/s/shorten` 会 404——因为 core 不代理这个路径，短链服务是独立进程（`src/shortener.js`）监听另一个端口。本地测试要把 base 换成短链服务的地址。

**大小上限（都已实测，不是估算）：**

| 内容 | 上限 | 说明 |
|---|---|---|
| 整个请求体 | **1 MiB**（1048576 B） | `core.js MAX_BODY`，nginx `client_max_body_size 1m` |
| 文件 | **512 KB** | 文件被 base64 两次，成本 ×1.778 |
| ASCII 文本 | ~786,000 字符 | 明文上限 786,184 B |
| 中文 | ~262,000 字符 | 3 B/字符 |
| Emoji | ~196,000 字符 | 4 B/字符 |

**每 IP 配额**：2 MiB 或 32 个粘贴，同时持有量（不是累计）。用完要先有粘贴被读掉或过期。

## 2. 全部参数

创建时 POST 到 `/api/paste` 的 JSON：

| 字段 | 必填 | 格式 / 取值 | 含义 |
|---|---|---|---|
| `id` | 是 | 16 位小写 hex | 粘贴 ID，随机 8 字节 |
| `ct` | 是 | base64url，≥23 字符 | 密文（AES-256-GCM，含 16 B tag） |
| `iv` | 是 | base64url，16 字符 | GCM nonce，随机 12 字节 |
| `salt` | 是 | base64url，11 字符 | PBKDF2 salt，随机 8 字节 |
| `claim` | 是 | base64url，64 字符 | 加密后的 proof（阅读凭证） |
| `claimIv` | 是 | base64url，16 字符 | claim 的 nonce；**不得等于 `iv`** |
| `claimHash` | 是 | base64url，43 字符 | proof 的 SHA-256 |
| `iterations` | 是 | 整数 100000–1000000 | PBKDF2 轮数，新粘贴用 1000000 |
| `burn` | 是 | 布尔 | 阅后即焚。`reads` 缺省时 `true` = 1 次 |
| `pinIp` | 是 | 布尔 | 锁定首个读者的 IP |
| `ttl` | 否 | 整数秒，60–`MAX_TTL_S` | 有效期。缺省 = 服务端 `TTL_HOURS` |
| `reads` | 否 | 整数 0–20 | 阅读次数上限。0 = 不限；缺省时由 `burn` 决定 |

服务端 `TTL_HOURS=168`，所以 `ttl` 最大 604800。常用值：`3600`（1 小时）、`21600`（6 小时，页面默认）、`86400`（1 天）、`259200`（3 天）、`604800`（7 天）。

`/s/shorten` 的 body：

| 字段 | 必填 | 取值 | 含义 |
|---|---|---|---|
| `url` | 是 | 必须是 `<origin>/?<16 hex>#<43 base64url>` | 要缩短的长链，**含密钥** |
| `len` | 否 | 整数 3–8，缺省 5 | 短码长度 |

短码字符集是 `[A-Za-z0-9]`。`len=5` 约 9 亿组合，`len=8` 约 2 万亿。

## 3. 密码参数

密码是**可选的客户端参数**，不进 API 请求体。它的作用方式：

```
密钥材料 = keyBytes(32 B 随机) ‖ password(UTF-8)
最终密钥 = PBKDF2-SHA256(密钥材料, salt, 1000000, 32)
```

- **不设密码**：链接本身就是密钥，和现在网页用法一致。接收方打开链接即解密。
- **设密码**：链接 + 密码两者缺一不可。**密码必须通过另一渠道告知接收方**（聊天、电话），不能写进同一个消息——否则密码毫无意义。
- Agent 应由用户明确决定是否设密码；用户没提就不设。设了就必须把密码单独告诉用户。

## 4. 脚本（scripts/ 目录）

四个文件，均已实测，含 `--help`。**Agent 优先直接用，不要重新实现。**

| 文件 | 用途 | 依赖 |
|---|---|---|
| `scripts/secure-online-clipboard-push.cjs` | 上传 | Node 18+，零第三方包 |
| `scripts/secure-online-clipboard-fetch.cjs` | 读回 | Node 18+，零第三方包 |
| `scripts/secure-online-clipboard-push.py` | 上传 | Python 3.8+ + `pip install cryptography` |
| `scripts/secure-online-clipboard-fetch.py` | 读回 | Python 3.8+ + `pip install cryptography` |

PBKDF2 在两边都用标准库（`node:crypto` / `hashlib`），只有 AES-GCM 在 Python 侧需要装包。Python 版在缺少该包时给出明确报错，不会静默失败。

**目标机没有 `cryptography` 时优先用 Node 版**：`node:crypto` 内置 AES-256-GCM，Node 18+ 零依赖，比在机器上装包更省事，也不必手写密码学代码。已实测可用的环境：Windows、WSL Debian、内网 devcenter（Debian 13 + Node 22，无任何 Python 加密库）。

### 上传

```bash
node scripts/secure-online-clipboard-push.cjs "内容" --short --len 6 --ttl 3600 --burn
python3 scripts/secure-online-clipboard-push.py "内容" --short --len 6 --ttl 3600 --burn
```

| 参数 | 说明 |
|---|---|
| `--file <path>` | 传文件而非文本（≤512 KB） |
| `--short` | 同时取短码 |
| `--len <3-8>` | 短码长度，默认 5 |
| `--ttl <60-604800>` | 有效期秒数，默认 21600（6 小时） |
| `--burn` | 阅后即焚 |
| `--reads <0-20>` | 阅读次数，0 = 不限。默认：`--burn` 时 1，否则 0 |
| `--pin-ip` | 锁定首个读者 IP |
| `--password <pw>` | 设密码（必须另行告知接收方） |
| `--base <url>` | 目标部署，默认 `$KHEPRI_BASE` 或 paste.vantolab.com |
| `--quiet` | 只输出链接，不输出 JSON |

输出 JSON：`{"long": "...", "short": "...", "shortError": "..."}`，`short` 仅在 `--short` 时出现。非法参数在本地就被拒绝，不会发出请求。

请求失败时脚本打印 `error: create failed <状态码>: <error 字段>` 后退出码 1。**不要把 `<error 字段>` 原样
转给用户**——那是机器码（如 `invalid paste fields`），第 6 节有它对应的人话。

### 参数怎么选（按场景）

| 场景 | 参数 |
|---|---|
| 一次性命令，执行完就该消失 | `--burn --ttl 3600` |
| 要反复执行的调试脚本 | 不加 `--burn`，`--ttl 86400` |
| 只给某一个特定的人看 | `--pin-ip`（但对方换网络会读不到，慎用） |
| 允许重试几次（比如接收方可能中断） | `--reads 3`，不加 `--burn` |
| 内容敏感，且能另行告知密码 | `--password <pw>`，密码走另一渠道 |
| 想短一点好手动抄 | `--short --len 6` |
| 大文件（接近上限） | 不要加 `--short`，长链已含全部信息 |

`--burn` 一旦被读就永久消失，无法重发。除非确认接收方能立即打开，否则优先 `--reads 3` 这类可重试组合。

### 读回

```bash
node scripts/secure-online-clipboard-fetch.cjs "https://paste.vantolab.com/?<id>#<key>" --out ./file.bin
python3 scripts/secure-online-clipboard-fetch.py "https://paste.vantolab.com/?<id>#<key>" --out ./file.bin
python3 scripts/secure-online-clipboard-fetch.py r7lld3            # 短码也行
```

| 参数 | 说明 |
|---|---|
| `<link>` 或 `<code>` | 长链，或裸短码 |
| `--out <path>` | 文件存到这里；不给则只打印元数据 |
| `--password <pw>` | 创建时设的密码 |
| `--base <url>` | 目标部署 |

**链接本身就够读回**，不需要额外保存任何密钥：`proof` 可以用密钥从 `claim` 里解出来，浏览器正是这么做的。

**跨语言互通已实测**：Node 上传的内容 Python 能读，反之亦然；400 KB 文件往返字节一致；中文与 emoji 无损；错误密码被 GCM 认证拒绝，不会吐出垃圾数据。

**失败时的输出**：脚本把服务端的 error 字段原样打印（`error: never existed`）并以退出码 1 结束，
**没有翻译层**。所以 Agent 拿到机器码后必须查第 6 节自己翻译，不能直接转给用户。

### 远端调试机首次使用

脚本在本仓库的 `skills/secure-online-clipboard/scripts/` 下，不在粘贴服务上托管。用 `scp` 带过去（一次性，之后那台机器永久可用）：

```bash
# 在你本机
scp skills/secure-online-clipboard/scripts/secure-online-clipboard-fetch.py 跳板机:~/

# 从跳板机到目标调试机
scp ~/secure-online-clipboard-fetch.py 调试机:~/

# 之后任何时候，短码直接取内容
python3 ~/secure-online-clipboard-fetch.py r7lld3
```

或者把那台机器能读到的位置当一个中转——比如先上传到某个调试机能访问的 git 仓库或内网 HTTP 服务，再 `curl -o secure-online-clipboard-fetch.py <那个地址>` 拉下来。

注意：**`curl` 和 `openssl enc` 都不能解密本协议**。curl 只有 TLS 能力，没有对称密码工具；`openssl enc` 明确不支持 AEAD（`AEAD ciphers not supported`）。必须有一个能跑 AES-256-GCM 的解释器（Node 18+ 或 Python 3.8+ + `cryptography`）。

## 5. 安全边界（必须遵守）

- **不要把长链和密码放进同一条消息。** 密码走另一渠道，否则等于没设。
- **不要把长链写进日志、commit 或任何会留存的地方。** 链接就是密钥。
- **短码服务能看到完整长链（含密钥）**，因为缩短的就是整个 URL。这是该服务既有的设计权衡（网页版同样如此，页面会提示 "the shortener holds the key from this link"）。内容敏感时优先用长链，或不设密码但只给长链。
- `pinIp` 会把粘贴绑到首个读取者的 IP。接收方如果换网络（手机切 Wi-Fi/4G）会读不到，谨慎使用。
- `--burn` 一旦被读就永久消失，无法重发。确认接收方能立即打开再用。

## 6. 错误码（全部实测，非推断）

**关键认知：API 返回的是机器码，不是网页上那句人话。** 网页的文案由前端硬编码，脚本拿不到。所以 Agent 必须自己把状态码 + error 字段翻译成用户能行动的话——下表第三列就是该说的话。

最容易被误判的一条：`400 invalid read proof` **同时意味着密码错和粘贴已消失**，服务端刻意不区分（免得探针能分辨某个 id 曾经存在过）。脚本无法进一步细分，只能告诉用户"密码可能不对，或者粘贴已经没了"。

### 创建 `POST /api/paste`

| HTTP | `error` | 实际含义 | 该告诉用户 |
|---|---|---|---|
| 200 | — | 成功 | — |
| 400 | `invalid paste fields` | 某字段格式/长度不符 | 脚本 bug，对照第 2 节自查 |
| 400 | `invalid expiry` | ttl 越界（<60 或 >604800） | 改用合法值 |
| 400 | `invalid read limit` | reads 越界（<0 或 >20） | 改用 0–20 |
| 400 | `Expected a JSON object` | body 是数组或标量 | 脚本 bug |
| 400 | `Invalid JSON` | body 不是合法 JSON | 脚本 bug |
| 409 | `id collision` | id 撞了 | 重新随机生成 id |
| 413 | `Request too large` | 超过 1 MiB | 减小文件或文本 |
| 415 | `Expected application/json` | 缺 Content-Type | 补 header |
| 429 | `paste quota exceeded` | 每 IP 2 MiB 或 32 个 | 等旧粘贴被读或过期 |
| 429 | `rate limited` | 超过 60 次/分 | 退避一分钟 |
| 500 | `storage error` | 服务端故障 | 重试或稍后再试 |
| 507 | `paste storage full` | 磁盘 5 GiB 满 | 只能等，或换部署 |

### 读取 `POST /api/paste/<id>`

| HTTP | `error` | 实际含义 | 该告诉用户 |
|---|---|---|---|
| 200 | — | 成功，返回 ct/iv | — |
| 400 | `bad id` | id 不是 16 位小写 hex | 链接坏了 |
| 400 | `invalid read proof` | **密码错，或粘贴已消失**（刻意不区分） | "密码可能不对，或者粘贴已经没了" |
| 404 | `never existed` | 该 id 从未存在 | "这个链接没有对应的内容" |
| 404 | `expired` | 超过 ttl | "已经过期了" |
| 404 | `pinned elsewhere` | IP 锁定，读取者换了网络 | "它锁在第一个读者的 IP 上，换网络读不到" |
| 429 | `rate limited` | 超过 60 次/分 | 退避一分钟 |

`GET /api/paste/<id>` 只返回 salt/iterations/claim，失败时用上面同样的码。

### 短码 `POST /s/shorten`、`GET /s/<code>`

| HTTP | `error` | 实际含义 | 该告诉用户 |
|---|---|---|---|
| 200 | — | 成功，返回短链 | — |
| 400 | `invalid paste destination` | url 不是本站粘贴链接 | 检查形如 `/?<16hex>#<43b64u>` |
| 400 | `len must be an integer from 3 to 8` | len 越界 | 改用 3–8 |
| 400 | `query parameters not allowed` | URL 带了 `?x=1` | 去掉 query |
| 403 | `origin not allowed` | 带了错误的 Origin 头 | 浏览器外调用不要带 Origin |
| 404 | `unknown code` | 短码不存在 | "没有这个短码" |
| 404 | `not found` | 路径不对 | 检查 URL |
| 405 | `method not allowed` | 方法用错 | GET 解析短码，POST 创建 |
| 429 | `rate limited` | 超过 120 次/分 | 退避一分钟 |
| 429 | `short link quota exceeded` | 每 IP 200 个短码 | 等旧的过期 |
| 503 | `short link storage full` | 总 10 万已满 | 用长链 |
| 503 | `could not allocate a short code` | 码分配失败 | 重试或换长度 |

网络层失败（fetch 抛异常、超时）没有 HTTP 状态码，脚本应报告"连不上服务"，不要猜成上面任何一种。
