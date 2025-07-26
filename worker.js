// worker.js
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Routing
    if (request.method === "POST" && path === "/api/signup") return signup(request, env);
    if (request.method === "POST" && path === "/api/login") return login(request, env);
    if (request.method === "POST" && path === "/api/logout") return logout(request, env);
    if (request.method === "POST" && path === "/api/delete") return deleteAccount(request, env);
    if (path === "/api/codes") return handleCodes(request, env);
    if (request.method === "POST" && path === "/api/invite") return handleInvite(request, env);

    return new Response("Not Found", { status: 404 });
  },
};

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });

const getJSON = async (req) => {
  try {
    return await req.json();
  } catch {
    return null;
  }
};

const hash = async (input, secret) => {
  const data = new TextEncoder().encode(input + secret);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
};

const uuid = () => crypto.randomUUID();
const now = () => Date.now();
const MAX_SESSION_AGE = 86400 * 1000; // 24h

async function getSession(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = cookie.match(/token=([^;]+)/)?.[1];
  if (!token) return null;
  const data = await env.CODES.get(`session_${token}`);
  if (!data) return null;
  const session = JSON.parse(data);
  if (session.expires && now() > session.expires) {
    await env.CODES.delete(`session_${token}`);
    return null;
  }
  return { token, ...session };
}

async function signup(request, env) {
  const body = await getJSON(request);
  const { username, password, invite } = body || {};
  if (!username || !password || !invite)
    return json({ error: "Missing fields" }, 400);

  const userKey = `user_${username.toLowerCase()}`;
  const exists = await env.CODES.get(userKey);
  if (exists) return json({ error: "Username taken" }, 400);

  const inviteData = await env.CODES.get(`invite_${invite}`);
  if (!inviteData) return json({ error: "Invalid invite" }, 400);
  const inviteObj = JSON.parse(inviteData);
  if (inviteObj.used >= (inviteObj.limit || 1))
    return json({ error: "Invite used up" }, 403);

  const passwordHash = await hash(password, env.TOKEN_SECRET);
  await env.CODES.put(
    userKey,
    JSON.stringify({ username, passwordHash, role: "user" })
  );

  inviteObj.used++;
  await env.CODES.put(`invite_${invite}`, JSON.stringify(inviteObj));

  return json({ success: true });
}

async function login(request, env) {
  const body = await getJSON(request);
  const { username, password } = body || {};
  if (!username || !password) return json({ error: "Missing" }, 400);

  const data = await env.CODES.get(`user_${username.toLowerCase()}`);
  if (!data) return json({ error: "Invalid" }, 401);
  const user = JSON.parse(data);
  const valid = (await hash(password, env.TOKEN_SECRET)) === user.passwordHash;
  if (!valid) return json({ error: "Invalid" }, 401);

  const token = uuid();
  const session = { user, expires: now() + MAX_SESSION_AGE };
  await env.CODES.put(`session_${token}`, JSON.stringify(session), {
    expirationTtl: MAX_SESSION_AGE / 1000,
  });

  return json({ token, user }, 200, {
    "Set-Cookie": `token=${token}; Max-Age=86400; Path=/; HttpOnly; SameSite=Strict`,
  });
}

async function logout(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: "Not logged in" }, 401);
  await env.CODES.delete(`session_${session.token}`);
  return json({ success: true }, 200, {
    "Set-Cookie": "token=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict",
  });
}

async function deleteAccount(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: "Not logged in" }, 401);
  const userKey = `user_${session.user.username.toLowerCase()}`;
  await env.CODES.delete(userKey);
  await env.CODES.delete(`session_${session.token}`);
  return json({ success: true });
}

async function handleCodes(request, env) {
  const session = await getSession(request, env);
  if (!session) return json({ error: "Unauthorized" }, 401);
  const userKey = `codes_${session.user.username.toLowerCase()}`;

  if (request.method === "GET") {
    const data = await env.CODES.get(userKey);
    return json({ codes: JSON.parse(data || "{}") });
  }

  if (request.method === "POST") {
    const body = await getJSON(request);
    if (!body) return json({ error: "Invalid body" }, 400);
    await env.CODES.put(userKey, JSON.stringify(body));
    return json({ success: true });
  }

  return json({ error: "Invalid method" }, 405);
}

async function handleInvite(request, env) {
  const session = await getSession(request, env);
  if (!session || session.user.role !== "admin")
    return json({ error: "Forbidden" }, 403);

  const body = await getJSON(request);
  const code = uuid();
  const limit = body?.limit || 1;

  await env.CODES.put(`invite_${code}`, JSON.stringify({ used: 0, limit }));
  return json({ code, limit });
}
