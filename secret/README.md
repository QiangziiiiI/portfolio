# 私密空间 / Hidden Space

基于 Cloudflare Pages Functions 的密码保护方案。

## 结构

```
functions/
  _middleware.js   # 全局中间件：加安全头 + 鉴权守卫
  api/
    verify.js      # POST 验证密码
    logout.js      # POST 清除cookie

secret/
  index.html       # 公开的密码输入页（入口）
  diary.html       # 受保护的示例页（可任意修改/扩展）
```

只要在 `secret/` 下新增任意 `.html` 文件（除 `index.html`），Worker 都会自动加锁保护。

## Cloudflare Pages 配置

部署到 Cloudflare Pages 后，需要在 **Settings → Environment variables** 配置两个变量：

| 变量名 | 值 | 说明 |
|--------|-----|------|
| `PASSWORD_HASH` | `你密码的 SHA-256` | 控制台/终端执行 `echo -n "你的密码" \| sha256sum` |
| `COOKIE_SECRET` | 随机 32+ 字符串 | 执行 `openssl rand -hex 32` 生成 |

⚠️ 改完密码或密钥后必须**重新部署**才会生效。

## 验证密码哈希的命令

**PowerShell**（Windows）:
```powershell
[BitConverter]::ToString(
  [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes("你的密码")
  )
).Replace('-', '').ToLower()
```

**Bash / macOS**:
```bash
echo -n "你的密码" | sha256sum
```

## 链接入口

可在首页底部加一个小链接指向 `/secret/`：

```html
<a href="/secret/" style="opacity:0.4">·</a>
```

## 特性

- ✅ 密码哈希存环境变量，源码里只有哈希
- ✅ HMAC 签名 cookie（防伪造）
- ✅ HttpOnly + Secure + SameSite=Strict cookie
- ✅ 密码会话 1 小时过期
- ✅ 失败次数限速（10次/分钟/IP）
- ✅ CSP / X-Frame-Options / HSTS 安全头
- ✅ 零额外费用（Cloudflare 免费额度 10万请求/天）

## 警告

这不是企业级安全方案。适合"朋友分享"、"未公开草稿"用途。
若需保护真正敏感内容，请用 [Cloudflare Access](https://www.cloudflare.com/products/zero-trust/access/)（带 OTP）。