
## ⭐ 1400 根因（2026-10-15 实测踩坑）
init_session 必须用 **snake_case**（env_info/robot_type/related_url/...），
用 camelCase（envInfo/robotType）会创建"异常会话"，后续 assistant/qa 返回 Code:1400。
QA body 同样必须 snake_case。两个接口都用 snake_case。

## 微信扫码登录可行性（研究结论）
- 拉二维码/换 token 接口：/cgi-bin/auth_login/get_wx_login_info（免登录可测）
  - 不带 code → code:51（缺参数）
  - 带假 code → code:40029 "invalid code"（走微信校验）
- 流程：get_wx_login_info 拿 appid/scope/state → 微信 open.weixin.qq.com/connect/qrconnect
  → 用户扫码 → 微信回调 ima.qq.com/login（带 code）→ 用 code 换登录态
- ⚠️ 关键卡点：redirect_uri 锁死 ima.qq.com，无法改 127.0.0.1 本地回调（与 workbuddy
  的 /plugin/auth/token 轮询接口不同，IMA 无此接口）→ **无法做到 workbuddy 式全自动扫码**
- 当前可行方案：客户端扩展（chrome.imaFrame getAccountInfo 由原生层持有 token）
  或用户手动粘一次 x-ima-cookie（refresh token 自动续期）
