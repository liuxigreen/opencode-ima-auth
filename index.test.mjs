// 自测：bkn 算法 / header / 请求体 / SSE 解析（全 mock，无需登录态）
// 运行：bun test index.test.mjs  或  node --test index.test.mjs
import { test } from "node:test"
import assert from "node:assert/strict"
import { _internal, ImaPlugin } from "./index.mjs"

const {
  cookieVal, bknOf, withFreshToken, buildHeaders, buildQuestion,
  refreshAccessToken, initSession, buildQaBody, extractBlock,
  translateImaStream, expiredErr, ROBOT,
} = _internal

const COOKIE =
  "IMA-GUID=abc123; IMA-UID=u_999; IMA-TOKEN=oldtok; IMA-REFRESH-TOKEN=refreshtok; other=1"

test("bknOf: DJB2 hash 与客户端一致", () => {
  // 用客户端同算法独立验算
  const ref = (e) => { let t = 5381; for (let i = 0; i < e.length; i++) t += (t << 5) + e.charCodeAt(i); return String(t & 2147483647) }
  for (const tok of ["oldtok", "abc", "x".repeat(64), "中文token"]) {
    assert.equal(bknOf(tok), ref(tok), `token=${tok}`)
  }
  assert.equal(bknOf(""), "")
})

test("cookieVal 解析字段", () => {
  assert.equal(cookieVal(COOKIE, "IMA-UID"), "u_999")
  assert.equal(cookieVal(COOKIE, "IMA-REFRESH-TOKEN"), "refreshtok")
  assert.equal(cookieVal(COOKIE, "NOPE"), "")
})

test("withFreshToken 替换/追加 IMA-TOKEN", () => {
  assert.match(withFreshToken(COOKIE, "newtok"), /IMA-TOKEN=newtok/)
  assert.doesNotMatch(withFreshToken(COOKIE, "newtok"), /IMA-TOKEN=oldtok/)
  assert.match(withFreshToken("a=1; b=2", "t"), /IMA-TOKEN=t/)
})

test("buildHeaders: bkn 由 token 算出 + 客户端身份", () => {
  const h = buildHeaders({ cookie: COOKIE, token: "tok123" })
  assert.equal(h["x-ima-cookie"].includes("IMA-TOKEN=tok123"), true)
  assert.equal(h["x-ima-bkn"], bknOf("tok123"))
  assert.equal("authorization" in h, false)   // 客户端不发 authorization，发了会被拒
  assert.equal(h["from_browser_ima"], "1")
  assert.equal(h["content-type"], "text/plain;charset=UTF-8")   // copilot 聊天格式
  assert.equal(h["extension_version"], "5.14.6")
  assert.match(h["x-ima-cookie"], /CLIENT-TYPE=256020/)          // 客户端身份
  assert.match(h["x-ima-cookie"], /WEB-VERSION=5\.14\.6/)

  // refresh 用旧 cookie 里的 token 算 bkn
  const rf = buildHeaders({ cookie: COOKIE, forRefresh: true, json: true })
  assert.equal(rf["x-ima-bkn"], bknOf("oldtok"))
  assert.equal(rf["content-type"], "application/json")
  assert.equal("authorization" in rf, false)
})

test("buildQuestion: 末条 user + system 前导", () => {
  assert.equal(
    buildQuestion([
      { role: "system", content: "你是助手" },
      { role: "user", content: "第一问" },
      { role: "assistant", content: "答" },
      { role: "user", content: [{ type: "text", text: "第二问" }] },
    ]),
    "[系统指令]\n你是助手\n\n[用户问题]\n第二问"
  )
  assert.equal(buildQuestion([{ role: "user", content: "hi" }]), "hi")
  assert.equal(buildQuestion([]), "")
})

test("refreshAccessToken: 成功 + 登录过期", async () => {
  const ok = async (url, init) => {
    assert.match(url, /auth_login\/refresh/)
    const b = JSON.parse(init.body)
    assert.equal(b.user_id, "u_999")
    assert.equal(b.refresh_token, "refreshtok")
    assert.equal(b.token_type, 14)
    return Response.json({ code: 0, token: "newtok", token_valid_time: "7200" })
  }
  const r = await refreshAccessToken({ cookie: COOKIE }, ok)
  assert.equal(r.token, "newtok")
  assert.equal(r.validFor, 7200)

  const dead = async () => Response.json({ code: 600002, msg: "expired" })
  await assert.rejects(refreshAccessToken({ cookie: COOKIE }, dead), (e) => e.signIn === "expired")
})

test("initSession: 带 knowledge_base_id（snake_case）", async () => {
  const f = async (url, init) => {
    assert.match(url, /init_session/)
    const b = JSON.parse(init.body)
    assert.equal(b.knowledge_base_info_with_folder.knowledge_base_id, "kb_1")
    assert.equal(b.related_url, "kb_1")
    assert.equal(b.env_info.robot_type, ROBOT.Copilot)   // 默认 copilot
    return Response.json({ code: 0, session_id: "sess_abc" })
  }
  assert.equal(await initSession({ cookie: COOKIE, token: "t", kbId: "kb_1" }, f), "sess_abc")
})

test("initSession: copilot 无知识库也能开会话", async () => {
  const f = async (url, init) => {
    const b = JSON.parse(init.body)
    assert.equal("knowledge_base_info_with_folder" in b, false)
    return Response.json({ code: 0, session_id: "s2" })
  }
  assert.equal(await initSession({ cookie: COOKIE, token: "t", kbId: "" }, f), "s2")
})

test("buildQaBody: copilot 用 robot_type=15 + command type 2000（实测）", () => {
  const b = buildQaBody({ question: "q?", sessionId: "s1", robotType: ROBOT.Copilot, cookie: COOKIE })
  assert.equal(b.robot_type, 15)
  assert.equal(b.question, "q?")
  assert.equal(b.question_type, 2)
  assert.equal(b.command_info.type, 2000)
  assert.deepEqual(b.command_info.copilot_qa_info, {})
  assert.ok(b.model_info.model_id.startsWith("official_"))
  assert.deepEqual(b.history_info, {})
  assert.deepEqual(b.client_tools, [])
  assert.match(b.device_info.uskey_bus_infos_input, /^abc123_\d+$/)

  // 知识库问答：robot_type=5 + command type 14
  const k = buildQaBody({ question: "q?", sessionId: "s1", robotType: ROBOT.Knowledge, cookie: COOKIE })
  assert.equal(k.robot_type, 5)
  assert.equal(k.command_info.type, 14)
  assert.ok("knowledge_qa_info" in k.command_info)
  assert.ok(!("model_id" in k.model_info))
})

test("extractBlock: copilot block 结构 + 兼容旧形态", () => {
  // copilot: Data.text_message.Text
  const blk = extractBlock({ Id: "b1", Type: "blockMessage", Data: { text_message: { Text: "你好" } } })
  assert.equal(blk.id, "b1")
  assert.equal(blk.text, "你好")
  // 空文本 / 删除事件 → null
  assert.equal(extractBlock({ Id: "q", Type: "queueWaiting", Data: { text_message: {} }, UpdateType: "delete" }), null)
  assert.equal(extractBlock({ Id: "t", Type: "blockThinking", Data: { thinking_message: { Message: "想" } } }), null)
  // 兼容旧知识库形态
  assert.equal(extractBlock({ msgs: [{ content: "hi" }] })?.text, "hi")
  assert.equal(extractBlock({ content: "c" })?.text, "c")
  assert.equal(extractBlock({ Text: "t" })?.text, "t")
  assert.equal(extractBlock({ code: 0 }), null)
})

const sse = (lines) =>
  new Response(
    new ReadableStream({
      start(c) {
        const enc = new TextEncoder()
        for (const l of lines) c.enqueue(enc.encode(l + "\n"))
        c.close()
      },
    }),
    { headers: { "content-type": "text/event-stream" } }
  )

const chunkTexts = (evs) =>
  evs.filter((e) => e.kind === "chunk" && e.hasText).map((e) => JSON.parse(e.data.slice(6)).choices[0].delta.content).join("")

test("translateImaStream: copilot block 累积去重", async () => {
  // 同一 Id 的 blockMessage，Text 为累积文本
  const res = sse([
    'data: {"Id":"b1","Type":"blockMessage","Data":{"text_message":{"Text":"你"}}}',
    'data: {"Id":"b1","Type":"blockMessage","Data":{"text_message":{"Text":"你好"}}}',
    'data: {"Id":"b1","Type":"blockMessage","Data":{"text_message":{"Text":"你好！"}}}',
    'data: {"Id":"t","Type":"blockThinking","Data":{"thinking_message":{"Message":"想"}}}',
    "data: [DONE]",
  ])
  const evs = []
  for await (const e of translateImaStream(res, { model: "ima-auto" })) evs.push(e)
  assert.equal(chunkTexts(evs), "你好！")   // 只输出了增量，无重复
  const end = evs.find((e) => e.kind === "end")
  assert.equal(end.chars, 3)
})

test("translateImaStream: 兼容旧 msgs 形态", async () => {
  const res = sse([
    'data: {"msgs":[{"content":"你"}]}',
    'data: {"msgs":[{"content":"好"}]}',
    'data: {"type":"knowledgeBase","processing":"搜索中..."}',
    "data: [DONE]",
  ])
  const evs = []
  for await (const e of translateImaStream(res, { model: "m" })) evs.push(e)
  assert.equal(chunkTexts(evs), "你好")
  const end = evs.find((e) => e.kind === "end")
  assert.equal(end.chars, 2)
  assert.equal(end.sawCode3, false)
})

test("translateImaStream: 累积事件去重（顶层 content）", async () => {
  const res = sse(['data: {"content":"ab"}', 'data: {"content":"abc"}', 'data: {"content":"abcd"}'])
  const evs = []
  for await (const e of translateImaStream(res, { model: "m" })) evs.push(e)
  assert.equal(chunkTexts(evs), "abcd")
})

test("translateImaStream: code=3 标记重试；600002 登录过期", async () => {
  const res = sse(['data: {"code":3,"msg":"busy"}'])
  const evs = []
  for await (const e of translateImaStream(res, { model: "m" })) evs.push(e)
  const end = evs.find((e) => e.kind === "end")
  assert.equal(end.chars, 0)
  assert.equal(end.sawCode3, true)

  const dead = sse(['data: {"code":600002,"msg":"expired"}'])
  await assert.rejects(
    (async () => { for await (const _ of translateImaStream(dead, { model: "m" })) {} })(),
    (e) => e.signIn === "expired"
  )
})

test("expiredErr 带 signIn 标记", () => {
  assert.equal(expiredErr("x").signIn, "expired")
})

test("plugin 形状：config/auth/provider 钩子齐全", async () => {
  const plugin = await ImaPlugin({ client: {} })
  const cfg = {}
  await plugin.config(cfg)
  assert.equal(cfg.provider.ima.name, "IMA Copilot")
  assert.equal(cfg.provider.ima.npm, "@ai-sdk/openai-compatible")
  assert.ok(cfg.provider.ima.models["ima-auto"])
  assert.ok(cfg.provider.ima.models["ima-knowledge"])
  assert.ok(cfg.provider.ima.models["ima-glm-5.3"])
  assert.equal(plugin.auth.provider, "ima")
  assert.equal(plugin.auth.methods[0].type, "api")
  assert.equal(typeof plugin.auth.loader, "function")
  assert.equal(typeof plugin.auth.refresh, "function")
  assert.equal(typeof plugin.auth.usage, "function")
  assert.equal(typeof plugin.auth.checkin, "function")
  assert.equal(plugin.provider.id, "ima")
})

test("checkin 钩子：code=0 -> claimed；已领 -> done", async () => {
  const calls = []
  const origFetch = globalThis.fetch
  try {
    globalThis.fetch = async (url, init) => {
      calls.push(url)
      if (url.includes("get_remaining_task_count")) return Response.json({ code: 0, data: { remaining_task_count: 42 } })
      if (url.includes("apply_task_trial")) return Response.json({ code: 0, msg: "领取成功" })
      return Response.json({ code: 0 })
    }
    const plugin = await ImaPlugin({ client: { auth: { set: async () => {} } } })
    const auth = { type: "api", key: COOKIE, access: "tok", expires: Date.now() + 3600_000, metadata: { uid: "u_999" } }
    const getAuth = async () => auth

    const r = await plugin.auth.checkin(getAuth)
    assert.equal(r.outcome, "claimed")
    assert.ok(calls.some((u) => u.includes("apply_task_trial")))

    globalThis.fetch = async () => Response.json({ code: 0, msg: "今日已领取" })
    const r2 = await plugin.auth.checkin(getAuth)
    assert.equal(r2.outcome, "done")

    globalThis.fetch = async () => Response.json({ code: 500, msg: "boom" })
    const r3 = await plugin.auth.checkin(getAuth)
    assert.equal(r3.outcome, "failed")
  } finally {
    globalThis.fetch = origFetch
  }
})

test("usage 钩子：读剩余算力", async () => {
  const origFetch = globalThis.fetch
  try {
    globalThis.fetch = async () => Response.json({ code: 0, data: { remaining_task_count: 88 } })
    const plugin = await ImaPlugin({ client: {} })
    const auth = { type: "api", key: COOKIE, access: "tok", expires: Date.now() + 3600_000, metadata: { uid: "u_999" } }
    const u = await plugin.auth.usage(async () => auth)
    assert.equal(u.user, "u_999")
    assert.ok(u.windows && u.windows.length === 1)
    assert.equal(u.windows[0].remaining, 88)
  } finally {
    globalThis.fetch = origFetch
  }
})
