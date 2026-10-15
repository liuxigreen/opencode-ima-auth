# @magpie-community/opencode-ima-auth

腾讯 ima 的 **copilot 任务模式**（MiMo-V2.6-Pro / GLM-5.3 / Kimi-K3 / MiniMax-M3 等 12 个模型）与**知识库问答**，作为 magpie / OpenCode 的 provider 插件。支持每日算力签到。

## 安装

在 magpie / OpenCode 里安装插件（git 源）：

```bash
# magpie CLI（若可用）
magpie plugin add liuxigreen/opencode-ima-auth

# 或在 magpie 配置里加：
# { "plugin": ["github:liuxigreen/opencode-ima-auth"] }
```

然后在 magpie 的 Providers 页选择 **IMA Copilot**，完成登录授权。

## 登录授权（一次性）

IMA 的微信扫码 `redirect_uri` 被腾讯锁死在 `ima.qq.com`，无法像其它插件那样本地回调自动完成，因此需要**手动粘一次登录态**：

1. 浏览器打开并登录 <https://ima.qq.com>
2. 按 `F12` → **Network** 面板 → 点任意一个 `/cgi-bin/` 请求
3. 在 **Request Headers** 里找到 `x-ima-cookie`，**整行复制**它的值
4. 粘到插件的登录框，知识库 ID 可留空（copilot 模式不需要）

粘一次后，插件用 `IMA-REFRESH-TOKEN` 自动续期（约 2 小时一次），之后无需再管。

> 也可以从已登录的 IMA 客户端抓 `x-ima-cookie`（F12 / 抓包），效果相同。

## 可用模型

登录后在 magpie 里选模型，前缀 `ima-`：

| 模型 ID | 说明 |
|---|---|
| `ima-auto` | 自动选择最优模型（默认）|
| `ima-mimo-v2.6-pro` | MiMo-V2.6-Pro |
| `ima-mimo-v2.6-flash` | MiMo-V2.6-Flash |
| `ima-glm-5.3` | GLM-5.3 |
| `ima-glm-5.3-flash` | GLM-5.3-Flash |
| `ima-minimax-m3` | MiniMax-M3 |
| `ima-kimi-k2.7-code` | Kimi-K2.7-Code |
| `ima-kimi-k2.8` | Kimi-K2.8-Preview |
| `ima-kimi-k3` | Kimi-K3 |
| `ima-deepseek-v4.1-flash` | DeepSeek-V4.1-Flash |
| `ima-hy3` / `ima-hy4-preview` | 腾讯混元 |
| `ima-knowledge` | 知识库问答（需填知识库 ID）|

## 说明

- 非官方逆向实现：接口随时可能变；登录态过期需重新粘一次 cookie。
- copilot 有每日算力限制，插件 `usage` 钩子会显示剩余算力。
- 低频使用；请遵守腾讯 ima 服务条款。

## License

MIT
