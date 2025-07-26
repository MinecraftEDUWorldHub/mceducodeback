export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;

    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status,
      headers: { "Content-Type": "application/json" }
    });

    const parseBody = async (req) => req.headers.get("content-type")?.includes("application/json") ? await req.json() : {};

    const authToken = request.headers.get("Authorization")?.replace("Bearer ", "");
    const user = authToken ? await env.KV.get(`token:${authToken}`) : null;
    const method = request.method;

    if (pathname === "/api/login" && method === "POST") {
      const { username, password } = await parseBody(request);
      const stored = await env.KV.get(`user:${username}`);
      if (!stored) return json({ error: "Invalid" }, 401);
      const userObj = JSON.parse(stored);
      if (userObj.password !== password) return json({ error: "Invalid" }, 401);

      const token = crypto.randomUUID();
      await env.KV.put(`token:${token}`, username, { expirationTtl: 86400 });
      return json({ token });
    }

    if (pathname === "/api/register" && method === "POST") {
      const { username, password } = await parseBody(request);
      if (await env.KV.get(`user:${username}`)) return json({ error: "Exists" }, 409);
      await env.KV.put(`user:${username}`, JSON.stringify({ password }));
      return json({ ok: true });
    }

    if (!user && pathname !== "/api/public") return json({ error: "Unauthorized" }, 401);

    if (pathname === "/api/data" && method === "GET") {
      const data = await env.KV.get(`data:${user}`);
      return json(JSON.parse(data || "[]"));
    }

    if (pathname === "/api/data" && method === "POST") {
      const data = await parseBody(request);
      await env.KV.put(`data:${user}`, JSON.stringify(data));
      return json({ ok: true });
    }

    if (pathname === "/api/public" && method === "GET") {
      const list = await env.KV.list({ prefix: "data:" });
      let all = [];

      for (const key of list.keys) {
        const data = await env.KV.get(key.name);
        if (data) {
          try {
            const parsed = JSON.parse(data);
            all.push(...parsed);
          } catch {}
        }
      }

      return json(all);
    }

    if (pathname === "/api/logout" && method === "POST") {
      if (authToken) await env.KV.delete(`token:${authToken}`);
      return json({ ok: true });
    }

    return json({ error: "Not found" }, 404);
  }
};
