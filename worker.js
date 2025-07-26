const TOKEN_TTL_SECONDS = 86400; // 1 day token expiration

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

    async function checkCreationPassword(input) {
      const stored = await env.CODES.get("config:creation_password");
      const expected = stored || "pickled";
      return input === expected;
    }

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
      if (invite.expireAt && Date.now() > invite.expireAt) return false;
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

    if (path === "/login.html") {
      return new Response(loginPage, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (path === "/signup") {
      return new Response(signupPage, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (path === "/") {
      return new Response(dashboardPage, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (path === "/api/register" && request.method === "POST") {
      const { username, password, creationPassword, inviteCode } = await parseJSON(
        request
      );

      const hasValidCreationPassword = await checkCreationPassword(creationPassword);
      const invite = await validateInviteCode(inviteCode);

      if (!hasValidCreationPassword && !invite) {
        return json({ error: "Must provide valid creation password or invite code" }, 403);
      }

      const existingUser = await env.CODES.get(`user:${username}`);
      if (existingUser) return json({ error: "Username exists" }, 400);

      await env.CODES.put(
        `user:${username}`,
        JSON.stringify({ password, admin: false })
      );

      if (invite && invite.oneTime) {
        await markInviteUsed(inviteCode);
      }

      return json({ ok: true });
    }

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

    if (path === "/api/load" && request.method === "GET") {
      const user = await requireAuth(request);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const raw = await env.CODES.get(`data:${user.username}`);
      return json(raw ? JSON.parse(raw) : {});
    }

    if (path === "/api/save" && request.method === "POST") {
      const user = await requireAuth(request);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const data = await parseJSON(request);
      await env.CODES.put(`data:${user.username}`, JSON.stringify(data));
      return json({ ok: true });
    }

    if (path === "/api/set-creation-password" && request.method === "POST") {
      const admin = await requireAdmin(request);
      if (!admin) return json({ error: "Unauthorized" }, 401);
      const { newPassword } = await parseJSON(request);
      if (!newPassword) return json({ error: "Missing new password" }, 400);
      await env.CODES.put("config:creation_password", newPassword);
      return json({ ok: true });
    }

    if (path === "/api/invites/create" && request.method === "POST") {
      const admin = await requireAdmin(request);
      if (!admin) return json({ error: "Unauthorized" }, 401);
      const { oneTime, expireSeconds } = await parseJSON(request);
      const code = uuid().slice(0, 8);

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

    if (path === "/api/invites/delete" && request.method === "POST") {
      const admin = await requireAdmin(request);
      if (!admin) return json({ error: "Unauthorized" }, 401);
      const { code } = await parseJSON(request);
      if (!code) return json({ error: "Missing invite code" }, 400);
      await env.CODES.delete(`invite:${code}`);
      return json({ ok: true });
    }

    if (path === "/api/account/delete" && request.method === "POST") {
      const user = await requireAuth(request);
      if (!user) return json({ error: "Unauthorized" }, 401);

      const { confirm } = await parseJSON(request);
      if (confirm !== true) return json({ error: "Confirmation required" }, 400);

      await env.CODES.delete(`user:${user.username}`);
      await env.CODES.delete(`data:${user.username}`);

      // Delete tokens for user
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

const loginPage = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Login</title></head>
<body>
<h2>Login</h2>
<form onsubmit="event.preventDefault();login();">
  <input id="username" placeholder="Username" required /><br/>
  <input id="password" type="password" placeholder="Password" required /><br/>
  <button type="submit">Login</button>
</form>
<p id="error" style="color:red;"></p>
<script>
async function login() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  if (res.ok) {
    localStorage.setItem("token", data.token);
    localStorage.setItem("admin", data.admin);
    location.href = "/";
  } else {
    document.getElementById("error").textContent = data.error || "Login failed";
  }
}
</script>
<p>Don't have an account? <a href="/signup">Sign up</a></p>
</body>
</html>`;

const signupPage = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Sign Up</title></head>
<body>
<h2>Sign Up</h2>
<form onsubmit="event.preventDefault();signup();">
  <input id="username" placeholder="Username" required /><br/>
  <input id="password" type="password" placeholder="Password" required /><br/>
  <input id="creationPassword" type="password" placeholder="Creation Password (optional)" /><br/>
  <input id="inviteCode" placeholder="Invite Code (optional)" /><br/>
  <button type="submit">Sign Up</button>
</form>
<p id="error" style="color:red;"></p>
<script>
async function signup() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const creationPassword = document.getElementById("creationPassword").value;
  const inviteCode = document.getElementById("inviteCode").value;
  const res = await fetch("/api/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password, creationPassword, inviteCode })
  });
  const data = await res.json();
  if (res.ok) {
    alert("Account created! Please login.");
    location.href = "/login.html";
  } else {
    document.getElementById("error").textContent = data.error || "Signup failed";
  }
}
</script>
<p>Already have an account? <a href="/login.html">Login</a></p>
</body>
</html>`;

const dashboardPage = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Dashboard</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 700px;
      margin: auto;
      padding: 20px;
    }
    input,
    button {
      margin: 5px 0;
      padding: 8px;
      width: 100%;
      max-width: 300px;
    }
    #logoutBtn {
      position: fixed;
      bottom: 10px;
      right: 10px;
    }
    table {
      border-collapse: collapse;
      width: 100%;
      margin-top: 10px;
    }
    th,
    td {
      border: 1px solid #ccc;
      padding: 8px;
      text-align: left;
    }
    .admin-section {
      border: 1px solid #999;
      padding: 10px;
      margin-top: 20px;
    }
    .error {
      color: red;
    }
    .success {
      color: green;
    }
  </style>
</head>
<body>
  <h2>Dashboard</h2>

  <h3>Your Minecraft Education Code</h3>
  <input id="worldName" placeholder="World Name" /><br />
  <input id="word1" placeholder="Word 1" maxlength="16" />
  <input id="word2" placeholder="Word 2" maxlength="16" />
  <input id="word3" placeholder="Word 3" maxlength="16" />
  <input id="word4" placeholder="Word 4" maxlength="16" /><br />
  <input id="worldConnectionId" placeholder="World Connection ID (optional)" /><br />
  <button onclick="saveCodes()">Save</button>
  <p id="saveStatus"></p>

  <hr />

  <h3>Invite Codes Management <small>(Admins only)</small></h3>
  <div id="inviteSection" style="display: none">
    <button onclick="loadInvites()">Refresh Invite List</button><br />
    <table id="invitesTable">
      <thead>
        <tr>
          <th>Code</th>
          <th>One-time</th>
          <th>Expires At</th>
          <th>Used</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
    <h4>Create New Invite</h4>
    <label><input type="checkbox" id="inviteOneTime" /> One-time use</label><br />
    <label>Expire in (seconds, 0 = never):
      <input type="number" id="inviteExpire" value="0" min="0" />
    </label>
    <br />
    <button onclick="createInvite()">Create Invite</button>
    <p id="inviteCreateStatus"></p>
  </div>

  <hr />

  <h3>Change Signup Password <small>(Admins only)</small></h3>
  <div id="creationPassSection" style="display: none">
    <input
      type="password"
      id="newCreationPassword"
      placeholder="New Signup Password"
    /><br />
    <button onclick="changeCreationPassword()">Update Signup Password</button>
    <p id="creationPassStatus"></p>
  </div>

  <hr />

  <h3>Delete Account</h3>
  <p><strong>Warning:</strong> This action is irreversible. Please confirm below to delete your account.</p>
  <label><input type="checkbox" id="confirmDelete" /> I understand and want to delete my account.</label><br />
  <button onclick="deleteAccount()">Delete Account</button>
  <p id="deleteStatus"></p>

  <button id="logoutBtn" onclick="logout()">Logout</button>

  <script>
    const token = localStorage.getItem("token");
    const admin = localStorage.getItem("admin") === "true";

    if (!token) {
      location.href = "/login.html";
    }

    if (admin) {
      document.getElementById("inviteSection").style.display = "block";
      document.getElementById("creationPassSection").style.display = "block";
      loadInvites();
    }

    async function loadInvites() {
      const res = await fetch("/api/invites/list", {
        headers: { Authorization: "Bearer " + token },
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data.error || "Failed to load invites");
        return;
      }
      const tbody = document.querySelector("#invitesTable tbody");
      tbody.innerHTML = "";
      data.invites.forEach((invite) => {
        const tr = document.createElement("tr");
        tr.innerHTML = \`
        <td>\${invite.code}</td>
        <td>\${invite.oneTime ? "Yes" : "No"}</td>
        <td>\${
          invite.expireAt ? new Date(invite.expireAt).toLocaleString() : "Never"
        }</td>
        <td>\${invite.used ? "Yes" : "No"}</td>
        <td><button onclick="deleteInvite('\${invite.code}')">Delete</button></td>
      \`;
        tbody.appendChild(tr);
      });
    }

    async function deleteInvite(code) {
      if (!confirm("Delete invite code " + code + "?")) return;
      const res = await fetch("/api/invites/delete", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      if (res.ok) {
        loadInvites();
        alert("Deleted invite " + code);
      } else {
        alert(data.error || "Failed to delete invite");
      }
    }

    async function createInvite() {
      const oneTime = document.getElementById("inviteOneTime").checked;
      let expireSeconds = Number(document.getElementById("inviteExpire").value);
      if (expireSeconds < 0 || isNaN(expireSeconds)) expireSeconds = 0;
      if (expireSeconds === 0) expireSeconds = null;

      const res = await fetch("/api/invites/create", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ oneTime, expireSeconds }),
      });
      const data = await res.json();
      if (res.ok) {
        document.getElementById(
          "inviteCreateStatus"
        ).textContent = \`Invite created: \${data.invite.code}\`;
        loadInvites();
      } else {
        document.getElementById("inviteCreateStatus").textContent =
          data.error || "Failed to create invite";
      }
    }

    async function changeCreationPassword() {
      const newPassword =
        document.getElementById("newCreationPassword").value.trim();
      if (!newPassword) {
        alert("Enter new password");
        return;
      }
      const res = await fetch("/api/set-creation-password", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ newPassword }),
      });
      const data = await res.json();
      if (res.ok) {
        document.getElementById("creationPassStatus").textContent =
          "Signup password updated!";
      } else {
        document.getElementById("creationPassStatus").textContent =
          data.error || "Failed to update";
      }
    }

    async function saveCodes() {
      const data = {
        worldName: document.getElementById("worldName").value,
        word1: document.getElementById("word1").value,
        word2: document.getElementById("word2").value,
        word3: document.getElementById("word3").value,
        word4: document.getElementById("word4").value,
        worldConnectionId: document.getElementById("worldConnectionId").value,
      };
      const res = await fetch("/api/save", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
      });
      const resp = await res.json();
      const statusEl = document.getElementById("saveStatus");
      if (res.ok) {
        statusEl.textContent = "Saved successfully!";
        statusEl.className = "success";
      } else {
        statusEl.textContent = resp.error || "Failed to save";
        statusEl.className = "error";
      }
    }

    async function loadCodes() {
      const res = await fetch("/api/load", {
        headers: { Authorization: "Bearer " + token },
      });
      const data = await res.json();
      if (res.ok) {
        document.getElementById("worldName").value = data.worldName || "";
        document.getElementById("word1").value = data.word1 || "";
        document.getElementById("word2").value = data.word2 || "";
        document.getElementById("word3").value = data.word3 || "";
        document.getElementById("word4").value = data.word4 || "";
        document.getElementById("worldConnectionId").value = data.worldConnectionId || "";
      } else {
        alert(data.error || "Failed to load codes");
      }
    }

    async function deleteAccount() {
      if (!document.getElementById("confirmDelete").checked) {
        alert("You must confirm deletion first.");
        return;
      }
      if (!confirm("This will permanently delete your account. Continue?")) return;
      const res = await fetch("/api/account/delete", {
        method: "POST",
        headers: {
          Authorization: "Bearer " + token,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ confirm: true }),
      });
      const data = await res.json();
      if (res.ok) {
        alert("Account deleted. Redirecting to signup.");
        localStorage.clear();
        location.href = "/signup";
      } else {
        alert(data.error || "Failed to delete account");
      }
    }

    function logout() {
      localStorage.clear();
      location.href = "/login.html";
    }

    loadCodes();
  </script>
</body>
</html>`;
