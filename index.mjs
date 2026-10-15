// Tencent IMA Copilot — magpie / OpenCode provider plugin
// ============================================================
// 把腾讯 ima 的 copilot（任务模式，带算力）与知识库问答暴露成 magpie provider。
//
// 逆向自官方 Mac 客户端 ima.copilot 2.3.0 的内置扩展
// （akncmfemomfkkgiffphoedpiioanbflo.crx，"IMA搜索" v4.12.2）。
// 接口、认证、bkn 算法均来自该扩展的前端代码，见同目录 FINDINGS.md。
//
// 认证：浏览器 / 客户端登录态的 x-ima-cookie（含 IMA-TOKEN / IMA-REFRESH-TOKEN
// / IMA-UID）。x-ima-bkn 由 IMA-TOKEN 经 DJB2 hash 本地算出，无需抓包。
//
// 非官方逆向实现：接口随时可能变，cookie 过期需重抓，低频使用。
import { randomUUID, randomBytes } from "node:crypto"

const PROVIDER = "ima"
const BASE = "https://ima.qq.com"
const PREFIX = "/cgi-bin"

// ---- 接口（实测，客户端 150.x + 扩展 5.14.6）----
const EP_REFRESH = `${PREFIX}/auth_login/refresh`
const EP_INIT_SESSION = `${PREFIX}/session_logic/init_session`
const EP_QA = `${PREFIX}/assistant/qa`                     // copilot 聊天 + 知识库问答（同一个）
const EP_MODELS = `${PREFIX}/model_manage/get_models`      // 模型列表（body {scene:0|1}）
const EP_COPILOT_HOME = `${PREFIX}/copilot_bot_manage/copilot_home`
const EP_REMAINING = `${PREFIX}/task_assistant/get_remaining_task_count`
const EP_APPLY_TRIAL = `${PREFIX}/task_assistant/apply_task_trial`   // 领取算力（签到）
const EP_TRIAL_RULE = `${PREFIX}/task_assistant/get_trial_rule`

// ---- robot_type（实测）----
const ROBOT = {
  Knowledge: 5,        // 知识库问答
  Copilot: 15,         // ⭐ copilot 任务模式（实测是 15，不是 12）
  Main: 10000,
}

// ---- command_info type（实测）----
const CMD_KNOWLEDGE_QA = 14
const CMD_COPILOT_QA = 2000

// ---- 客户端身份标识（copilot 需要，否则报"版本过旧"）----
// 由客户端 150.0.7871.5383 + 内置扩展 5.14.6 抓包得出
const CLIENT = {
  clientType: "256020",       // 网页是 256053
  webVersion: "5.14.6",       // 须非空
  extensionVersion: "5.14.6",
  origin: "chrome-extension://ebbbfiigemhmjadjbckcodajdmnceamb",
  ua:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 " +
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 IMA/150.0.7871.5383",
}

// copilot 模型（scene=1）。默认"自动选择最优模型"
const COPILOT_MODELS = {
  auto: { model_id: "official_100000", model_type: 100000, name: "自动选择最优模型" },
  "mimo-v2.6-pro": { model_id: "official_paid_ep-8ab4w2pt", model_type: 110000, name: "MiMo-V2.6-Pro" },
  "mimo-v2.6-flash": { model_id: "official_paid_ep-mkoeiyvs", model_type: 110000, name: "MiMo-V2.6-Flash" },
  "glm-5.3": { model_id: "official_paid_ep-6mnmwpgi", model_type: 110000, name: "GLM-5.3" },
  "glm-5.3-flash": { model_id: "official_paid_ep-orngvu1u", model_type: 110000, name: "GLM-5.3-Flash" },
  "minimax-m3": { model_id: "official_paid_ep-41wf1s9g", model_type: 110000, name: "MiniMax-M3" },
  "kimi-k2.7-code": { model_id: "official_paid_ep-iwb7hj0b", model_type: 110000, name: "Kimi-K2.7-Code" },
  "kimi-k2.8": { model_id: "official_paid_ep-4zyh6vvm", model_type: 110000, name: "Kimi-K2.8-Preview" },
  "kimi-k3": { model_id: "official_paid_ep-4iwlzjkt", model_type: 110000, name: "Kimi-K3" },
  "deepseek-v4.1-flash": { model_id: "official_paid_ep-i2azx8ko", model_type: 110000, name: "DeepSeek-V4.1-Flash" },
  "hy3": { model_id: "official_paid_hy3", model_type: 110000, name: "Hy3" },
  "hy4-preview": { model_id: "official_paid_hy4-preview", model_type: 110000, name: "Hy4 preview" },
}

const REFRESH_LEAD_MS = 5 * 60 * 1000
const IDLE_TIMEOUT_MS = 180_000
const RETRY_DELAY_MS = 2000
const MAX_ATTEMPTS = 2
const LOGIN_EXPIRED_CODES = new Set([600001, 600002, 600003])

const DEFAULT_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0"

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

/** 从 cookie 串取某个键的值。 */
function cookieVal(cookie, name) {
  if (!cookie) return ""
  const m = new RegExp(`${name}=([^;]+)`).exec(cookie)
  return m ? m[1].trim() : ""
}

/**
 * x-ima-bkn 算法：DJB2 hash，取正 31 位。
 * 逆向自客户端 input-cache-service：`Vg = e => { let t=5381; ... return t & 2147483647 }`
 */
function bknOf(token) {
  if (!token) return ""
  try {
    let t = 5381
    for (let i = 0; i < token.length; i++) {
      t += (t << 5) + token.charCodeAt(i)
    }
    return String(t & 2147483647)
  } catch {
    return ""
  }
}

/** 把新 token 写回 cookie 串（替换或追加 IMA-TOKEN）。 */
function withFreshToken(cookie, token) {
  if (!token) return cookie
  if (/IMA-TOKEN=[^;]*/.test(cookie)) {
    return cookie.replace(/IMA-TOKEN=[^;]*/, `IMA-TOKEN=${token}`)
  }
  return cookie.replace(/;\s*$/, "") + `; IMA-TOKEN=${token}`
}

/**
 * 组装请求头。
 * copilot 需要"客户端身份"：CLIENT-TYPE=256020 + 非空 WEB-VERSION/extension_version，
 * 否则服务端返回"当前版本过旧"。这些写进 x-ima-cookie 与扩展头。
 */
function buildHeaders({ cookie, token, json = false, forRefresh = false }) {
  const tok = forRefresh ? cookieVal(cookie, "IMA-TOKEN") : token || cookieVal(cookie, "IMA-TOKEN")
  // 把客户端身份补进 cookie（PLATFORM/CLIENT-TYPE/WEB-VERSION 已是 cookie 的一部分时保留原值）
  let c = forRefresh ? cookie : withFreshToken(cookie, token)
  c = ensureClientIdentity(c)
  // ⚠️ 只发客户端实际发的头。多发的 referer/cache-control/sec-fetch-*/accept-language
  // 会触发服务端校验，返回 Code:1400（实测）。
  const headers = {
    accept: json ? "application/json" : "text/event-stream",
    // copilot 聊天实测用 text/plain；JSON 接口用 application/json
    "content-type": json ? "application/json" : "text/plain;charset=UTF-8",
    extension_version: CLIENT.extensionVersion,
    from_browser_ima: "1",
    origin: CLIENT.origin,
    "x-ima-cookie": c,
    "user-agent": CLIENT.ua,
  }
  if (tok) headers["x-ima-bkn"] = bknOf(tok)
  // 注意：客户端抓包不含 authorization 头（cookie 里的 IMA-TOKEN + x-ima-bkn 已足够；
  // 加了反而被服务端拒，返回 Code:1400）。故此处不发 authorization。
  return headers
}

/** 在 cookie 串里补齐客户端身份字段（覆盖旧的/缺失的）。 */
function ensureClientIdentity(cookie) {
  let c = cookie
  const set = (name, val) => {
    if (new RegExp(`${name}=`).test(c)) c = c.replace(new RegExp(`${name}=[^;]*`), `${name}=${val}`)
    else c = c.replace(/;\s*$/, "") + `; ${name}=${val}`
  }
  // 仅当 cookie 里 CLIENT-TYPE 不是客户端值时才覆盖（保留用户已登录的完整 cookie 其它字段）
  if (cookieVal(c, "CLIENT-TYPE") !== CLIENT.clientType) set("CLIENT-TYPE", CLIENT.clientType)
  if (!cookieVal(c, "WEB-VERSION")) set("WEB-VERSION", CLIENT.webVersion)
  return c
}

const expiredErr = (msg) => Object.assign(new Error(msg), { signIn: "expired" })

function contentToText(content) {
  if (typeof content === "string") return content
  if (Array.isArray(content)) {
    return content.map((p) => (typeof p === "string" ? p : p?.text || "")).join("")
  }
  return ""
}

/** 把 OpenAI 的 messages 压成 IMA 的单条 question（system 作前导）。 */
function buildQuestion(messages = []) {
  const sys = []
  let lastUser = ""
  for (const m of messages || []) {
    const text = contentToText(m.content)
    if (m.role === "system" && text) sys.push(text)
    else if (m.role === "user" && text.trim()) lastUser = text
  }
  if (!lastUser.trim()) return ""
  return sys.length
    ? `[系统指令]\n${sys.join("\n")}\n\n[用户问题]\n${lastUser}`
    : lastUser
}

/** 设备信息（deviceInfo）。客户端用真实设备指纹，这里给稳定的合成值。 */
function deviceInfo(cookie) {
  const guid = cookieVal(cookie, "IMA-GUID") || "magpie"
  return {
    uskey: Buffer.from(randomBytes(32)).toString("base64"),
    uskeyBusInfosInput: `${guid}_${Math.floor(Date.now() / 1000)}`,
  }
}

/* ------------------------------------------------------------------ */
/* IMA API                                                             */
/* ------------------------------------------------------------------ */

async function refreshAccessToken({ cookie, userId, refreshToken }, fetchImpl = fetch) {
  const uid = userId || cookieVal(cookie, "IMA-UID")
  const rt = refreshToken || cookieVal(cookie, "IMA-REFRESH-TOKEN") || cookieVal(cookie, "IMA-TOKEN")
  if (!uid || !rt) throw new Error("cookie 缺少 IMA-UID / IMA-REFRESH-TOKEN，请重新抓取登录态")
  const res = await fetchImpl(`${BASE}${EP_REFRESH}`, {
    method: "POST",
    headers: buildHeaders({ cookie, forRefresh: true, json: true }),
    body: JSON.stringify({ user_id: uid, refresh_token: rt, token_type: 14 }),
    signal: AbortSignal.timeout(30_000),
  })
  if (!res.ok) throw new Error(`刷新接口 HTTP ${res.status}`)
  const data = await res.json().catch(() => ({}))
  if (data.code === 0 && data.token) {
    return {
      token: data.token,
      validFor: parseInt(data.token_valid_time, 10) || 7200,
      userId: data.user_id || uid,
    }
  }
  if (LOGIN_EXPIRED_CODES.has(data.code)) {
    throw expiredErr(`IMA 登录已过期 (code=${data.code})，请重新抓取 x-ima-cookie`)
  }
  throw new Error(`Token 刷新失败 code=${data.code}: ${data.msg || "未知错误"}`)
}

async function initSession({ cookie, token, kbId, robotType }, fetchImpl = fetch) {
  const res = await fetchImpl(`${BASE}${EP_INIT_SESSION}`, {
    method: "POST",
    headers: buildHeaders({ cookie, token, json: true }),
    body: JSON.stringify({
      env_info: { robot_type: robotType ?? ROBOT.Copilot, interact_type: 0 },
      related_url: kbId || "",
      scene_type: 1,
      msgs_limit: 10,
      forbid_auto_add_to_history_list: false,
      ...(kbId ? { knowledge_base_info_with_folder: { knowledge_base_id: kbId, folder_ids: [] } } : {}),
    }),
    signal: AbortSignal.timeout(30_000),
  })
  if (!res.ok) throw new Error(`init_session HTTP ${res.status}`)
  const data = await res.json().catch(() => ({}))
  if (data.code === 0 && data.session_id) return data.session_id
  if (LOGIN_EXPIRED_CODES.has(data.code)) {
    throw expiredErr(`IMA 登录已过期 (code=${data.code})，请重新抓取登录态`)
  }
  throw new Error(`init_session 失败 code=${data.code}: ${data.msg || "未知错误"}`)
}

/**
 * 问答请求体。实测格式（snake_case + block 响应）。
 * - copilot: robot_type=15, command_info{type:2000, copilot_qa_info:{}}
 * - 知识库: robot_type=5, command_info{type:14, knowledge_qa_info:{...}}
 */
function buildQaBody({ question, sessionId, robotType, cookie, model, mode }) {
  const uskey = randomBytes(32).toString("base64")
  const guid = cookieVal(cookie, "IMA-GUID") || "magpie"
  const m = model || COPILOT_MODELS.auto
  const isCopilot = robotType === ROBOT.Copilot
  return {
    session_id: sessionId,
    robot_type: robotType,
    question,
    question_type: 2,
    client_id: randomUUID(),
    command_info: isCopilot
      ? { type: CMD_COPILOT_QA, copilot_qa_info: {} }
      : { type: CMD_KNOWLEDGE_QA, knowledge_qa_info: { tags: [], knowledge_ids: [], media_id_infos: [] } },
    model_info: {
      ...(isCopilot ? { model_id: m.model_id } : {}),
      model_type: m.model_type,
      enable_enhancement: false,
    },
    history_info: {},
    device_info: {
      uskey,
      uskey_bus_infos_input: `${guid}_${Math.floor(Date.now() / 1000)}`,
    },
    client_tools: [],
  }
}

/**
 * 从 SSE 事件对象里提取增量文本。copilot 用 block 结构：
 * - j.Data.text_message.Text （同一 Id 内为累积文本）
 * - 兼容旧的 msgs[].content / content / Text
 * 返回 { id, text }（text 为该块的累积全文），或 null（非文本事件）。
 */
function extractBlock(json) {
  if (!json || typeof json !== "object") return null
  const id = json.Id
  // copilot block 结构
  const tm = json.Data?.text_message
  if (tm && typeof tm.Text === "string") {
    // queueWaiting 的删除事件是空的，跳过
    if (json.UpdateType === "delete" || !tm.Text) return null
    return { id: id || "_", text: tm.Text, kind: "message" }
  }
  // 旧知识库形态
  if (Array.isArray(json.msgs)) {
    for (const mm of json.msgs) {
      if (mm && typeof mm === "object" && mm.content) return { id: "_", text: String(mm.content), kind: "message" }
    }
    return null
  }
  if (typeof json.content === "string" && json.content) return { id: "_", text: json.content, kind: "message" }
  if (typeof json.Text === "string" && json.Text) return { id: "_", text: json.Text, kind: "message" }
  return null
}

function openAIChunk({ id, created, model, delta, finish }) {
  return `data: ${JSON.stringify({
    id,
    object: "chat.completion.chunk",
    created,
    model,
    choices: [{ index: 0, delta, finish_reason: finish ?? null }],
  })}\n\n`
}

/** 把 IMA SSE 转成 OpenAI chat chunk 流（支持 copilot block 累积去重）。 */
async function* translateImaStream(imaRes, { model, signal }) {
  const id = `chatcmpl-ima-${Date.now().toString(36)}`
  const created = Math.floor(Date.now() / 1000)
  const reader = imaRes.body.getReader()
  const decoder = new TextDecoder()
  let buf = ""
  // 每个块 Id 的已输出前缀，用于增量去重
  const seen = new Map()
  let chars = 0
  let sawCode3 = false
  let lastDataAt = Date.now()

  const idleTimer = setInterval(() => {
    if (Date.now() - lastDataAt > IDLE_TIMEOUT_MS) {
      reader.cancel(new Error(`IMA 流 ${IDLE_TIMEOUT_MS / 1000}s 无数据，超时`)).catch(() => {})
    }
  }, 10_000)
  const onAbort = () => reader.cancel().catch(() => {})
  signal?.addEventListener("abort", onAbort, { once: true })

  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      lastDataAt = Date.now()
      buf += decoder.decode(value, { stream: true })
      let idx
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx).trim()
        buf = buf.slice(idx + 1)
        if (!line.startsWith("data:")) continue
        const payload = line.slice(5).trim()
        if (!payload || payload === "[DONE]") continue
        let json
        try {
          json = JSON.parse(payload)
        } catch {
          continue
        }
        // 顶层错误码（知识库形态：{code, msg}）
        if (typeof json.Code === "number" && json.Code !== 0 && json.Msg && !json.Data) {
          if (json.Code === 1) throw new Error(`IMA: ${json.Msg}`)
          if (json.Code === 3) { sawCode3 = true; continue }
        }
        if (typeof json.code === "number" && json.code !== 0) {
          if (LOGIN_EXPIRED_CODES.has(json.code)) {
            throw expiredErr(`IMA 登录已过期 (code=${json.code})，请重新抓取登录态`)
          }
          if (json.code === 3) { sawCode3 = true; continue }
        }
        const blk = extractBlock(json)
        if (!blk || !blk.text) continue
        // 累积文本按 Id 做增量去重
        const prev = seen.get(blk.id) || ""
        let delta
        if (blk.text.length >= prev.length && blk.text.startsWith(prev)) {
          delta = blk.text.slice(prev.length)
          seen.set(blk.id, blk.text)
        } else {
          // 非累积：直接当增量
          delta = blk.text
          seen.set(blk.id, prev + blk.text)
        }
        if (delta) {
          chars += delta.length
          yield { kind: "chunk", hasText: true, data: openAIChunk({ id, created, model, delta: { content: delta } }) }
        }
      }
    }
  } finally {
    clearInterval(idleTimer)
    signal?.removeEventListener("abort", onAbort)
  }
  yield { kind: "chunk", hasText: false, data: openAIChunk({ id, created, model, delta: {}, finish: "stop" }) }
  yield { kind: "chunk", hasText: false, data: "data: [DONE]\n\n" }
  yield { kind: "end", chars, sawCode3 }
}

const SSE_HEADERS = {
  "content-type": "text/event-stream",
  "cache-control": "no-cache",
  "x-magpie-sign-in": "kept",
}

/* ------------------------------------------------------------------ */
/* usage & check-in                                                    */
/* ------------------------------------------------------------------ */

/** 查剩余算力。 */
async function fetchRemaining({ cookie, token }) {
  const res = await fetch(`${BASE}${EP_REMAINING}`, {
    method: "POST",
    headers: buildHeaders({ cookie, token, json: true }),
    body: JSON.stringify({}),
    signal: AbortSignal.timeout(20_000),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const data = await res.json().catch(() => ({}))
  if (LOGIN_EXPIRED_CODES.has(data.code)) throw expiredErr(`IMA 登录已过期 (code=${data.code})`)
  if (data.code !== 0) throw new Error(`code=${data.code}: ${data.msg || ""}`)
  return data
}

/** 领取算力（= 每日签到）。 */
async function applyTrial({ cookie, token }) {
  const res = await fetch(`${BASE}${EP_APPLY_TRIAL}`, {
    method: "POST",
    headers: buildHeaders({ cookie, token, json: true }),
    body: JSON.stringify({}),
    signal: AbortSignal.timeout(20_000),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const data = await res.json().catch(() => ({}))
  if (LOGIN_EXPIRED_CODES.has(data.code)) throw expiredErr(`IMA 登录已过期 (code=${data.code})`)
  return data
}

/* ------------------------------------------------------------------ */
/* the plugin                                                          */
/* ------------------------------------------------------------------ */

export const ImaPlugin = async ({ client }, options) => {
  const opts = options || {}
  // 默认用 copilot 任务模式；opts.mode = "knowledge" 可切到知识库问答
  const defaultMode = opts.mode === "knowledge" ? "knowledge" : "mission"

  const log = (level, msg) => {
    try {
      client?.app?.log?.({ level, service: "ima", message: msg })
    } catch { /* not under magpie */ }
  }

  const renew = async (auth) => {
    const uid = auth.metadata?.uid || cookieVal(auth.key, "IMA-UID")
    const rt = auth.refresh || cookieVal(auth.key, "IMA-REFRESH-TOKEN") || cookieVal(auth.key, "IMA-TOKEN")
    try {
      const { token, validFor } = await refreshAccessToken({ cookie: auth.key, userId: uid, refreshToken: rt })
      // 关键：把新 token 写回 cookie（auth.key），否则 init_session / QA 仍用旧 token → 600001
      const freshKey = withFreshToken(auth.key, token)
      const next = {
        ...auth,
        key: freshKey,
        access: token,
        expires: Date.now() + Math.max(0, validFor - 300) * 1000,
      }
      try {
        await client.auth.set({ path: { id: PROVIDER }, body: next })
      } catch { /* keep going */ }
      return next
    } catch (e) {
      if (e?.signIn === "expired") throw e
      throw expiredErr(`IMA token 刷新失败：${e.message}`)
    }
  }

  const ensureFresh = async (auth) => {
    if (auth.access && auth.expires && Date.now() < auth.expires - REFRESH_LEAD_MS) return auth
    return renew(auth)
  }

  const jsonError = (status, message) =>
    new Response(JSON.stringify({ error: { message, code: status } }), {
      status,
      headers: { "content-type": "application/json" },
    })

  /** 一次问答。返回 Response，或 { retry: true }（Code=3 自愈）。 */
  const askOnce = async ({ auth, kbId, model, question, wantStream, mode, signal }) => {
    // copilot 和知识库问答都走 /cgi-bin/assistant/qa；区别在 robot_type 与 command_info
    const isCopilot = mode !== "knowledge"
    const robotType = isCopilot ? ROBOT.Copilot : ROBOT.Knowledge
    const resolvedModel = isCopilot
      ? (COPILOT_MODELS[String(model).replace(/^ima-/, "")] || COPILOT_MODELS.auto)
      : COPILOT_MODELS.auto

    const sessionId = await initSession({ cookie: auth.key, token: auth.access, kbId: kbId || "", robotType })
    const qaBody = JSON.stringify(
      buildQaBody({ question, sessionId, robotType, cookie: auth.key, model: resolvedModel, mode })
    )

    const res = await fetch(`${BASE}${EP_QA}`, {
      method: "POST",
      headers: buildHeaders({ cookie: auth.key, token: auth.access }),
      body: qaBody,
      signal,
    })

    if (!res.ok) {
      const text = await res.text().catch(() => "")
      if (res.status === 401 || res.status === 403) {
        throw expiredErr(`IMA 拒绝了登录态 (HTTP ${res.status})，请重新抓取 x-ima-cookie`)
      }
      throw new Error(`IMA 问答接口 HTTP ${res.status}: ${text.slice(0, 200)}`)
    }
    const ctype = res.headers.get("content-type") || ""
    if (!ctype.includes("text/event-stream")) {
      const data = await res.json().catch(() => ({}))
      if (LOGIN_EXPIRED_CODES.has(data.code)) {
        throw expiredErr(`IMA 登录已过期 (code=${data.code})`)
      }
      throw new Error(`IMA 返回非流式响应 code=${data.code}: ${data.msg || ctype}`)
    }

    if (!wantStream) {
      let content = ""
      const gen = translateImaStream(res, { model, signal })
      for await (const ev of gen) {
        if (ev.kind === "chunk" && ev.hasText) {
          const m = /"content":"((?:[^"\\]|\\.)*)"/.exec(ev.data)
          if (m) content += JSON.parse(`"${m[1]}"`)
        } else if (ev.kind === "end") {
          if (ev.chars === 0 && ev.sawCode3) return { retry: true }
        }
      }
      return {
        response: new Response(
          JSON.stringify({
            id: `chatcmpl-ima-${Date.now().toString(36)}`,
            object: "chat.completion",
            created: Math.floor(Date.now() / 1000),
            model,
            choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }],
          }),
          { headers: { "content-type": "application/json" } }
        ),
      }
    }

    // 流式：先缓冲到首个文本块，Code=3 空流才能重试
    const gen = translateImaStream(res, { model, signal })
    const head = []
    let streaming = false
    let end = null
    for await (const ev of gen) {
      if (ev.kind === "chunk") {
        head.push(ev.data)
        if (ev.hasText) {
          streaming = true
          break
        }
      } else {
        end = ev
        break
      }
    }
    if (!streaming) {
      if (end && end.chars === 0 && end.sawCode3) return { retry: true }
      return { response: new Response(head.join(""), { headers: SSE_HEADERS }) }
    }
    const out = new ReadableStream({
      async start(controller) {
        const enc = new TextEncoder()
        try {
          for (const b of head) controller.enqueue(enc.encode(b))
          for await (const ev of gen) {
            if (ev.kind === "chunk") controller.enqueue(enc.encode(ev.data))
          }
          controller.close()
        } catch (e) {
          controller.error(e)
        }
      },
    })
    return { response: new Response(out, { headers: SSE_HEADERS }) }
  }

  return {
    config: async (cfg) => {
      cfg.provider ??= {}
      cfg.provider[PROVIDER] ??= {
        name: "IMA Copilot",
        npm: "@ai-sdk/openai-compatible",
        api: `${BASE}${PREFIX}/assistant`,
        models: {
          "ima-auto": { name: "IMA 自动选择最优模型", limit: { context: 32000, output: 16000 }, tool_call: false },
          ...Object.fromEntries(
            Object.entries(COPILOT_MODELS)
              .filter(([k]) => k !== "auto")
              .map(([k, m]) => [`ima-${k}`, { name: `IMA ${m.name}`, limit: { context: 32000, output: 16000 }, tool_call: false }])
          ),
          "ima-knowledge": { name: "IMA 知识库问答", limit: { context: 32000, output: 8000 }, tool_call: false },
        },
      }
    },

    auth: {
      provider: PROVIDER,
      maxConcurrency: 1,
      methods: [
        {
          type: "api",
          label: "IMA 登录态（x-ima-cookie）",
          prompts: [
            {
              type: "password",
              key: "cookie",
              message: "粘贴 x-ima-cookie（拿法：浏览器打开 ima.qq.com 并登录 → F12 → Network → 任意 /cgi-bin/ 请求 → Request Headers → 复制 x-ima-cookie 整行值）",
              validate: (v) =>
                /IMA-TOKEN=|IMA-REFRESH-TOKEN=/.test(v || "")
                  ? undefined
                  : "不像 x-ima-cookie：未找到 IMA-TOKEN / IMA-REFRESH-TOKEN，请整行复制",
            },
            {
              type: "text",
              key: "kb",
              message: "知识库 ID（可选；copilot 模式可留空，仅知识库问答需要）",
            },
          ],
          async authorize(inputs) {
            const cookie = inputs?.cookie?.trim()
            const kb = inputs?.kb?.trim() || ""
            if (!cookie) return { type: "failed", error: "x-ima-cookie 必填" }
            // 提醒：网页版拿的 cookie 没有客户端身份，插件会自动补 CLIENT-TYPE/WEB-VERSION
            const uid = cookieVal(cookie, "IMA-UID")
            const rt = cookieVal(cookie, "IMA-REFRESH-TOKEN") || cookieVal(cookie, "IMA-TOKEN")
            if (!rt) return { type: "failed", error: "cookie 缺少 IMA-REFRESH-TOKEN，请从登录后的请求里复制完整 cookie" }
            try {
              const { token, validFor } = await refreshAccessToken({ cookie, userId: uid, refreshToken: rt })
              // 用刷新后的 token 更新 stored cookie，保证后续请求都带新 token
              const freshCookie = withFreshToken(cookie, token)
              return {
                type: "success",
                key: freshCookie,
                metadata: { kb, uid },
                access: token,
                refresh: rt,
                expires: Date.now() + Math.max(0, validFor - 300) * 1000,
                accountId: uid || "ima-account",
              }
            } catch (e) {
              return { type: "failed", error: `登录态校验失败：${e.message}`.slice(0, 500) }
            }
          },
        },
      ],

      refreshLead: REFRESH_LEAD_MS,
      async refresh(auth) {
        const next = await renew({ ...auth, access: undefined, expires: 0 })
        return { access: next.access, expires: next.expires }
      },

      /** magpie 的用量钩子：显示剩余算力。 */
      async usage(getAuth) {
        const auth = await getAuth()
        if (!auth?.key) return { error: "not signed in" }
        try {
          const a = await ensureFresh(auth)
          const d = await fetchRemaining({ cookie: a.key, token: a.access })
          const remaining = d?.data?.remaining_task_count ?? d?.data?.remaining_count ?? d?.remaining ?? null
          const out = {
            user: a.metadata?.uid || cookieVal(a.key, "IMA-UID") || "IMA",
            signIn: "kept",
          }
          if (remaining != null) {
            out.windows = [{
              label: "算力",
              used: 0,
              limit: Number(remaining),
              remaining: Number(remaining),
              text: `剩余算力 ${remaining}`,
            }]
          }
          return out
        } catch (e) {
          return { error: e?.message ?? String(e), ...(e?.signIn ? { signIn: e.signIn } : {}) }
        }
      },

      /** magpie 的每日签到钩子：领取算力。 */
      async checkin(getAuth) {
        const auth = await getAuth()
        if (!auth?.key) return { outcome: "ineligible", message: "未登录" }
        try {
          const a = await ensureFresh(auth)
          const d = await applyTrial({ cookie: a.key, token: a.access })
          const msg = String(d.msg || "")
          const already = /已(领|签)|already|重复|received/i.test(msg)
          if (d.code === 0) {
            // code=0 但文案说"已领过" → done，否则 claimed
            return already
              ? { outcome: "done", message: msg || "今日已领取" }
              : { outcome: "claimed", message: msg || "已领取算力" }
          }
          if (already) return { outcome: "done", message: msg }
          return { outcome: "failed", message: `code=${d.code}: ${msg}` }
        } catch (e) {
          if (e?.signIn === "expired") throw e
          return { outcome: "failed", message: e?.message ?? String(e) }
        }
      },

      async loader(getAuth) {
        return {
          baseURL: `${BASE}${PREFIX}/task_assistant`,
          async fetch(input, init = {}) {
            let auth = await getAuth()
            if (!auth || !auth.key) {
              return jsonError(401, "IMA 未登录：请先执行 magpie plugin login ima")
            }
            let req
            try {
              const raw = typeof init.body === "string" ? init.body : Buffer.from(init.body || "").toString()
              req = JSON.parse(raw)
            } catch {
              return jsonError(400, "无法解析 chat completions 请求体")
            }
            const model = req.model || "ima-copilot"
            const mode = model.includes("knowledge") ? "knowledge" : defaultMode
            const question = buildQuestion(req.messages)
            if (!question) return jsonError(400, "没有可发送的用户消息")
            const wantStream = req.stream !== false
            const kbId = auth.metadata?.kb

            auth = await ensureFresh(auth)

            let lastError = null
            for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
              if (attempt > 0) await new Promise((r) => setTimeout(r, RETRY_DELAY_MS))
              try {
                const out = await askOnce({ auth, kbId, model, question, wantStream, mode, signal: init.signal })
                if (out.retry) continue
                return out.response
              } catch (e) {
                if (e?.signIn === "expired") throw e
                lastError = e
              }
            }
            throw lastError || new Error("IMA 问答失败")
          },
        }
      },
    },

    provider: {
      id: PROVIDER,
      async models(provider) {
        return provider.models
      },
    },
  }
}

// 供测试的内部控制
export const _internal = {
  PROVIDER, BASE, PREFIX, ROBOT, CLIENT, COPILOT_MODELS,
  CMD_COPILOT_QA, CMD_KNOWLEDGE_QA,
  cookieVal, bknOf, withFreshToken, buildHeaders, ensureClientIdentity,
  contentToText, buildQuestion,
  refreshAccessToken, initSession, buildQaBody,
  extractBlock, translateImaStream, expiredErr,
  fetchRemaining, applyTrial,
  EP_REFRESH, EP_INIT_SESSION, EP_QA, EP_MODELS, EP_COPILOT_HOME,
  EP_REMAINING, EP_APPLY_TRIAL, EP_TRIAL_RULE,
}

export default { id: PROVIDER, server: ImaPlugin }
