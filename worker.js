
import { v4 as uuidv4 } from "uuid";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Routes
    if (pathname === "/") {
      return new Response(dashboardHTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (pathname === "/login.html") {
      return new Response(loginHTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }

    if (pathname === "/public") {
      const all = await listAllCodes(env);
      return new Response(JSON.stringify(all), {
        headers: { "Content-Type": "application/json" },
      });
    }

    if (pathname === "/api/login" && request.method === "POST") {
      const { username, password } = await request.json();
      const stored = await env.CODE_KV.get(`user:${username}`, { type: "json" });
      if (!stored || stored.password !== password)
        return new Response(JSON.stringify({ error: "Invalid" }), { status: 401 });
      const token = uuidv4();
      await env.CODE_KV.put(`token:${token}`, username);
      return Response.json({ token });
    }

    if (pathname === "/api/register" && request.method === "POST") {
      const { username, password } = await request.json();
      const exists = await env.CODE_KV.get(`user:${username}`);
      if (exists) return new Response(JSON.stringify({ error: "Exists" }), { status: 400 });
      await env.CODE_KV.put(`user:${username}`, JSON.stringify({ password }));
      return Response.json({ ok: true });
    }

    if (pathname === "/api/data") {
      const auth = request.headers.get("Authorization") || "";
      const token = auth.replace("Bearer ", "");
      const username = await env.CODE_KV.get(`token:${token}`);
      if (!username) return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });

      if (request.method === "GET") {
        const data = await env.CODE_KV.get(`data:${username}`, { type: "json" }) || [];
        return Response.json(data);
      }

      if (request.method === "POST") {
        const codes = await request.json();
        await env.CODE_KV.put(`data:${username}`, JSON.stringify(codes));
        return Response.json({ ok: true });
      }
    }

    return new Response("Not Found", { status: 404 });
  }
};

async function listAllCodes(env) {
  const list = await env.CODE_KV.list();
  const users = list.keys.filter(k => k.name.startsWith("data:"));
  const output = [];
  for (const userKey of users) {
    const codes = await env.CODE_KV.get(userKey.name, { type: "json" });
    if (Array.isArray(codes)) output.push(...codes);
  }
  return output;
}

const loginHTML = `
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h2>Login</h2>
  <form id="loginForm">
    <input type="text" id="username" placeholder="Username" required />
    <input type="password" id="password" placeholder="Password" required />
    <button type="submit">Login</button>
    <p id="errorMsg" style="color:red"></p>
  </form>
  <script>
    const form = document.getElementById('loginForm');
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const username = form.username.value;
      const password = form.password.value;
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password })
      });
      const data = await res.json();
      if (res.ok) {
        localStorage.setItem('token', data.token);
        location.href = '/';
      } else {
        document.getElementById('errorMsg').textContent = data.error;
      }
    });
  </script>
</body>
</html>
`;

const dashboardHTML = `
<!DOCTYPE html>
<html>
<head><title>Code Manager</title></head>
<body>
  <h2>Minecraft World Code Manager</h2>
  <div id="codes"></div>
  <button onclick="save()">Save</button>
  <button onclick="logout()" style="position: fixed; bottom: 10px; right: 10px;">Logout</button>
  <script>
    let token = localStorage.getItem("token");
    if (!token) location.href = "/login.html";

    async function load() {
      const res = await fetch("/api/data", {
        headers: { Authorization: "Bearer " + token }
      });
      const codes = await res.json();
      const container = document.getElementById("codes");
      container.innerHTML = "";
      codes.forEach((code, i) => {
        container.innerHTML += \`
          <div>
            <input value="\${code.name}" placeholder="World Name" />
            <input value="\${code.word1}" placeholder="Word 1" />
            <input value="\${code.word2}" placeholder="Word 2" />
            <input value="\${code.word3}" placeholder="Word 3" />
            <input value="\${code.word4}" placeholder="Word 4" />
            <input value="\${code.connection || ''}" placeholder="Connection ID (optional)" />
          </div>\`;
      });
    }

    async function save() {
      const divs = document.querySelectorAll("#codes > div");
      const codes = Array.from(divs).map(d => {
        const inputs = d.querySelectorAll("input");
        return {
          name: inputs[0].value,
          word1: inputs[1].value,
          word2: inputs[2].value,
          word3: inputs[3].value,
          word4: inputs[4].value,
          connection: inputs[5].value
        };
      });
      await fetch("/api/data", {
        method: "POST",
        headers: {
          "Authorization": "Bearer " + token,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(codes)
      });
      alert("Saved!");
    }

    function logout() {
      localStorage.removeItem("token");
      location.href = "/login.html";
    }

    load();
  </script>
</body>
</html>
`;
