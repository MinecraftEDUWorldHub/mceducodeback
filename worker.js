const loginHtml = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>Login - Minecraft Code Manager</title>
  <style>
    body { font-family: sans-serif; max-width: 400px; margin: 3rem auto; padding: 1rem; background: #f0f0f0; }
    input, button { width: 100%; padding: 0.5rem; margin: 0.5rem 0; }
    button { cursor: pointer; }
    .error { color: red; }
  </style>
</head>
<body>
  <h2>Login</h2>
  <form id="loginForm">
    <input type="text" id="username" placeholder="Username" required />
    <input type="password" id="password" placeholder="Password" required />
    <button type="submit">Login</button>
    <p id="errorMsg" class="error"></p>
  </form>

  <script>
    const form = document.getElementById('loginForm');
    const errorMsg = document.getElementById('errorMsg');

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errorMsg.textContent = '';
      const username = form.username.value.trim();
      const password = form.password.value;

      try {
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (res.ok && data.token) {
          localStorage.setItem('token', data.token);
          window.location.href = '/';  // Redirect to main editor
        } else {
          errorMsg.textContent = data.error || 'Login failed';
        }
      } catch (err) {
        errorMsg.textContent = 'Network error';
      }
    });
  </script>
</body>
</html>`;

const indexHtml = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
  <title>Minecraft Code Manager</title>
  <style>
    body { font-family: sans-serif; max-width: 600px; margin: 2rem auto; padding: 1rem; background: #f4f4f4; }
    input, button { width: 100%; padding: 0.5rem; margin: 0.3rem 0; }
    button { cursor: pointer; }
    #logout { position: fixed; bottom: 20px; right: 20px; }
    .code-entry { background: white; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
  </style>
</head>
<body>
  <h1>Minecraft Education Codes Manager</h1>
  <div id="codesContainer"></div>
  <button id="addNew">Add New Code</button>
  <button id="saveBtn">Save</button>
  <button id="logout">Logout</button>

  <script>
    const token = localStorage.getItem('token');
    if (!token) {
      alert('Not logged in');
      window.location.href = '/login.html';
    }

    async function fetchCodes() {
      const res = await fetch('/api/data', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      if (res.status === 401) {
        alert('Unauthorized. Please login again.');
        localStorage.removeItem('token');
        window.location.href = '/login.html';
        return [];
      }
      return await res.json();
    }

    function createCodeEntry(data = {}) {
      const div = document.createElement('div');
      div.className = 'code-entry';

      div.innerHTML = `
        <input type="text" placeholder="World Name" class="worldName" value="${data.name || ''}" />
        <input type="text" placeholder="Word 1" class="word1" value="${data.word1 || ''}" />
        <input type="text" placeholder="Word 2" class="word2" value="${data.word2 || ''}" />
        <input type="text" placeholder="Word 3" class="word3" value="${data.word3 || ''}" />
        <input type="text" placeholder="Word 4" class="word4" value="${data.word4 || ''}" />
        <input type="text" placeholder="World Connection ID (optional)" class="conn" value="${data.conn || ''}" />
        <button class="removeBtn">Remove</button>
      `;

      div.querySelector('.removeBtn').onclick = () => {
        div.remove();
      };

      return div;
    }

    async function init() {
      const container = document.getElementById('codesContainer');
      const codes = await fetchCodes();
      codes.forEach(code => {
        container.appendChild(createCodeEntry(code));
      });

      document.getElementById('addNew').onclick = () => {
        container.appendChild(createCodeEntry());
      };

      document.getElementById('saveBtn').onclick = async () => {
        const allCodes = [];
        container.querySelectorAll('.code-entry').forEach(div => {
          allCodes.push({
            name: div.querySelector('.worldName').value.trim(),
            word1: div.querySelector('.word1').value.trim(),
            word2: div.querySelector('.word2').value.trim(),
            word3: div.querySelector('.word3').value.trim(),
            word4: div.querySelector('.word4').value.trim(),
            conn: div.querySelector('.conn').value.trim(),
          });
        });

        const res = await fetch('/api/data', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + token
          },
          body: JSON.stringify(allCodes)
        });

        if (res.ok) {
          alert('Saved successfully!');
        } else if (res.status === 401) {
          alert('Unauthorized. Please login again.');
          localStorage.removeItem('token');
          window.location.href = '/login.html';
        } else {
          alert('Failed to save data.');
        }
      };

      document.getElementById('logout').onclick = async () => {
        await fetch('/api/logout', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + token }
        });
        localStorage.removeItem('token');
        window.location.href = '/login.html';
      };
    }

    init();
  </script>
</body>
</html>`;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json" },
      });

    const parseBody = async (req) =>
      req.headers.get("content-type")?.includes("application/json")
        ? await req.json()
        : {};

    // Serve static files
    if (pathname === "/login.html") {
      return new Response(loginHtml, {
        headers: { "Content-Type": "text/html;charset=UTF-8" },
      });
    }

    if (pathname === "/" || pathname === "/index.html") {
      return new Response(indexHtml, {
        headers: { "Content-Type": "text/html;charset=UTF-8" },
      });
    }

    // Authentication helpers
    const authHeader = request.headers.get("Authorization");
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.slice(7)
      : null;
    const username = token ? await env.KV.get(`token:${token}`) : null;

    // API routes

    if (pathname === "/api/register" && method === "POST") {
      const { username, password } = await parseBody(request);
      if (!username || !password) return json({ error: "Missing fields" }, 400);
      if (await env.KV.get(`user:${username}`))
        return json({ error: "User exists" }, 409);
      await env.KV.put(`user:${username}`, JSON.stringify({ password }));
      return json({ ok: true });
    }

    if (pathname === "/api/login" && method === "POST") {
      const { username, password } = await parseBody(request);
      if (!username || !password) return json({ error: "Missing fields" }, 400);
      const stored = await env.KV.get(`user:${username}`);
      if (!stored) return json({ error: "Invalid" }, 401);
      const userObj = JSON.parse(stored);
      if (userObj.password !== password) return json({ error: "Invalid" }, 401);
      const newToken = crypto.randomUUID();
      await env.KV.put(`token:${newToken}`, username, { expirationTtl: 86400 });
      return json({ token: newToken });
    }

    if (pathname === "/api/logout" && method === "POST") {
      if (token) await env.KV.delete(`token:${token}`);
      return json({ ok: true });
    }

    if (!username && !pathname.startsWith("/api/public"))
      return json({ error: "Unauthorized" }, 401);

    if (pathname === "/api/data") {
      if (method === "GET") {
        const data = await env.KV.get(`data:${username}`);
        return json(JSON.parse(data || "[]"));
      }
      if (method === "POST") {
        const data = await parseBody(request);
        await env.KV.put(`data:${username}`, JSON.stringify(data));
        return json({ ok: true });
      }
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

    return json({ error: "Not found" }, 404);
  },
};
