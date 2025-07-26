const TOKEN_TTL_SECONDS = 86400; // Default 1 day

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json" },
      });

    const parseJSON = async (req) => {
      try {
        return await req.json();
      } catch {
        return {};
      }
    };

    const uuid = () => crypto.randomUUID();

    // --- Auth helpers ---

    async function getUserFromToken(auth) {
      if (!auth?.startsWith("Bearer ")) return null;
      const token = auth.slice(7);
      const tokenDataRaw = await env.CODES.get(`token:${token}`);
      if (!tokenDataRaw) return null;
      try {
        return JSON.parse(tokenDataRaw);
      } catch {
        return null;
      }
    }

    async function requireAuth(req) {
      const user = await getUserFromToken(req.headers.get("Authorization"));
      if (!user) return null;
      return user;
    }

    async function requireAdmin(req) {
      const user = await requireAuth(req);
      if (!user || !user.admin) return null;
      return user;
    }

    // --- Creation password check ---

    async function checkCreationPassword(input) {
      const stored = await env.CODES.get("config:creation_password");
      const expected = stored || "pickled";
      return input === expected;
    }

    // --- Invite validation ---

    async function validateInviteCode(inviteCode) {
      if (!inviteCode) return false;
      const inviteRaw = await env.CODES.get(`invite:${inviteCode}`);
      if (!inviteRaw) return false;
      let invite;
      try {
        invite = JSON.parse(inviteRaw);
      } catch {
        return false;
      }
      // Check expiration
      if (invite.expireAt && Date.now() > invite.expireAt) return false;

      // If one-time use, check if used
      if (invite.oneTime && invite.used) return false;

      return invite;
    }

    async function markInviteUsed(inviteCode) {
      const inviteRaw = await env.CODES.get(`invite:${inviteCode}`);
      if (!inviteRaw) return;
      let invite = JSON.parse(inviteRaw);
      if (invite.oneTime) {
        invite.used = true;
        await env.CODES.put(`invite:${inviteCode}`, JSON.stringify(invite));
      }
    }

    // --- Routes ---

    // Serve HTML pages
    if (path === "/login.html") {
      return new Response(loginPage, { headers: { "Content-Type": "text/html" } });
    }
    if (path === "/signup") {
      return new Response(signupPage, { headers: { "Content-Type": "text/html" } });
    }
    if (path === "/") {
      return new Response(dashboardPage, { headers: { "Content-Type": "text/html" } });
    }

    // API: Register new user with invite and creation password
    if (path === "/api/register" && request.method === "POST") {
      const { username, password, creationPassword, inviteCode } = await parseJSON(request);

      if (!(await checkCreationPassword(creationPassword))) {
        return json({ error: "Invalid creation password" }, 403);
      }

      const invite = await validateInviteCode(inviteCode);
      if (!invite) return json({ error: "Invalid or used invite code" }, 403);

      const existingUser = await env.CODES.get(`user:${username}`);
      if (existingUser) return json({ error: "Username exists" }, 400);

      // Save user (no hashing for simplicity - consider hashing passwords!)
      await env.CODES.put(`user:${username}`, JSON.stringify({ password, admin: false }));

      // Mark invite used if one-time
      if (invite.oneTime) {
        await markInviteUsed(inviteCode);
      }

      return json({ ok: true });
    }

    // API: Login
    if (path === "/api/login" && request.method === "POST") {
      const { username, password } = await parseJSON(request);
      const userRaw = await env.CODES.get(`user:${username}`);
      if (!userRaw) return json({ error: "Invalid" }, 401);
      const user = JSON.parse(userRaw);
      if (user.password !== password) return json({ error: "Invalid" }, 401);

      const token = uuid();
      const tokenData = {
        username,
        admin: user.admin,
        createdAt: Date.now(),
      };

      await env.CODES.put(`token:${token}`, JSON.stringify(tokenData), {
        expirationTtl: TOKEN_TTL_SECONDS,
      });

      return json({ token, admin: user.admin });
    }

    // API: Load user codes
    if (path === "/api/load" && request.method === "GET") {
      const user = await requireAuth(request);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const raw = await env.CODES.get(`data:${user.username}`);
      return json(raw ? JSON.parse(raw) : {});
    }

    // API: Save user codes
    if (path === "/api/save" && request.method === "POST") {
      const user = await requireAuth(request);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const data = await parseJSON(request);
      await env.CODES.put(`data:${user.username}`, JSON.stringify(data));
      return json({ ok: true });
    }

    // API: Change creation password (admin only)
    if (path === "/api/set-creation-password" && request.method === "POST") {
      const admin = await requireAdmin(request);
      if (!admin) return json({ error: "Unauthorized" }, 401);
      const { newPassword } = await parseJSON(request);
      if (!newPassword) return json({ error: "Missing new password" }, 400);
      await env.CODES.put("config:creation_password", newPassword);
      return json({ ok: true });
    }

    // API: Invite code management (admin only)

    // Create invite
    if (path === "/api/invites/create" && request.method === "POST") {
      const admin = await requireAdmin(request);
      if (!admin) return json({ error: "Unauthorized" }, 401);
      const { oneTime, expireSeconds } = await parseJSON(request);
      const code = uuid().slice(0, 8); // shorter code

      const invite = {
        code,
        oneTime: !!oneTime,
        expireAt: expireSeconds ? Date.now() + expireSeconds * 1000 : null,
        used: false,
        createdBy: admin.username,
      };

      await env.CODES.put(`invite:${code}`, JSON.stringify(invite));
      return json({ ok: true, invite });
    }

    // List invites
    if (path === "/api/invites/list" && request.method === "GET") {
      const admin = await requireAdmin(request);
      if (!admin) return json({ error: "Unauthorized" }, 401);

      const list = await env.CODES.list({ prefix: "invite:" });
      const invites = [];
      for (const key of list.keys) {
        const raw = await env.CODES.get(key.name);
        if (!raw) continue;
        invites.push(JSON.parse(raw));
      }
      return json({ invites });
    }

    // Delete invite
    if (path.startsWith("/api/invites/delete") && request.method === "POST") {
      const admin = await requireAdmin(request);
      if (!admin) return json({ error: "Unauthorized" }, 401);
      const { code } = await parseJSON(request);
      if (!code) return json({ error: "Missing invite code" }, 400);
      await env.CODES.delete(`invite:${code}`);
      return json({ ok: true });
    }

    // Account deletion (confirm in body)
    if (path === "/api/account/delete" && request.method === "POST") {
      const user = await requireAuth(request);
      if (!user) return json({ error: "Unauthorized" }, 401);

      const { confirm } = await parseJSON(request);
      if (confirm !== true) return json({ error: "Confirmation required" }, 400);

      // Delete user data + tokens + user record
      await env.CODES.delete(`user:${user.username}`);
      await env.CODES.delete(`data:${user.username}`);

      // Delete all tokens matching user.username
      // Note: Cloudflare KV has no direct query, so we list and filter
      const keys = await env.CODES.list({ prefix: "token:" });
      for (const key of keys.keys) {
        const tokenRaw = await env.CODES.get(key.name);
        if (!tokenRaw) continue;
        try {
          const tokenData = JSON.parse(tokenRaw);
          if (tokenData.username === user.username) {
            await env.CODES.delete(key.name);
          }
        } catch {}
      }

      return json({ ok: true });
    }

    // Public endpoint: all shared codes (all users combined)
    if (path === "/public") {
      const keys = await env.CODES.list({ prefix: "data:" });
      const allCodes = [];
      for (const key of keys.keys) {
        const raw = await env.CODES.get(key.name);
        if (!raw) continue;
        try {
          const codes = JSON.parse(raw);
          if (Array.isArray(codes)) allCodes.push(...codes);
          else allCodes.push(codes);
        } catch {}
      }
      return json(allCodes);
    }

    return new Response("Not found", { status: 404 });
  },
};

// Below: Embedded pages omitted for brevity.
// You’d add the dashboard HTML + login + signup pages with UI controls for:
// - managing invites (list/create/delete)
// - changing creation password
// - deleting account (with confirmation prompt)
// - editing codes and logout

// (If you want, I can provide those too)
