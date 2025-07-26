import { v4 as uuidv4 } from 'uuid';

const htmlPages = {
  login: `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login</title></head>
<body>
  <h2>Login</h2>
  <input id="username" placeholder="Username" /><br />
  <input id="password" type="password" placeholder="Password" /><br />
  <button onclick="login()">Login</button>
  <script>
    async function login() {
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: {'Content-Type':'application/json'},
        body: JSON.stringify({username, password})
      });
      const data = await res.json();
      if(data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('role', data.role);
        localStorage.setItem('username', data.username);
        window.location.href = '/dashboard';
      } else alert(data.error || 'Login failed');
    }
  </script>
</body></html>`,

  dashboard: `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Dashboard</title></head>
<body>
  <h2>My Worlds</h2>
  <button onclick="logout()" style="position: fixed; bottom: 10px; right: 10px;">Logout</button>
  <button onclick="createWorld()">Create New World</button>
  <button onclick="changeMyPassword()">Change My Password</button>
  <div id="worlds"></div>
  <script>
    const token = localStorage.getItem('token');
    if(!token) location.href = '/login';

    async function fetchWorlds() {
      const res = await fetch('/api/worlds', {
        headers: { Authorization: token }
      });
      const data = await res.json();
      const container = document.getElementById('worlds');
      container.innerHTML = '';
      data.forEach(world => {
        const div = document.createElement('div');
        div.style = 'border:1px solid #ccc; margin:10px; padding:10px;';
        div.innerHTML = \`
          <input placeholder="World Name" value="\${world.worldName || ''}" data-id="\${world.id}" class="worldName" /><br/>
          <input placeholder="Word 1" value="\${world.word1 || ''}" class="word1" /><br/>
          <input placeholder="Word 2" value="\${world.word2 || ''}" class="word2" /><br/>
          <input placeholder="Word 3" value="\${world.word3 || ''}" class="word3" /><br/>
          <input placeholder="Word 4" value="\${world.word4 || ''}" class="word4" /><br/>
          <input placeholder="World Connection ID (optional)" value="\${world.connectionId || ''}" class="connectionId" /><br/>
          <small>Owner: \${world.owner}</small><br/>
          <button onclick="saveWorld(this)">Save</button>
        \`;
        container.appendChild(div);
      });
    }

    async function saveWorld(button) {
      const div = button.parentElement;
      const id = div.querySelector('.worldName').dataset.id;
      const worldName = div.querySelector('.worldName').value;
      const word1 = div.querySelector('.word1').value;
      const word2 = div.querySelector('.word2').value;
      const word3 = div.querySelector('.word3').value;
      const word4 = div.querySelector('.word4').value;
      const connectionId = div.querySelector('.connectionId').value;

      const res = await fetch('/api/update-world', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', Authorization: token},
        body: JSON.stringify({id, data: {worldName, word1, word2, word3, word4, connectionId}})
      });
      const data = await res.json();
      if(data.success) alert('Saved!');
      else alert('Failed: ' + (data.error || 'unknown'));
    }

    async function createWorld() {
      const res = await fetch('/api/create-world', {
        method: 'POST',
        headers: { Authorization: token }
      });
      const data = await res.json();
      if(data.success) fetchWorlds();
      else alert('Failed to create world');
    }

    async function changeMyPassword() {
      const newPw = prompt('Enter your new password');
      if(!newPw) return alert('Cancelled');
      const username = localStorage.getItem('username');
      const res = await fetch('/api/change-password', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', Authorization: token},
        body: JSON.stringify({username, newPassword: newPw})
      });
      const data = await res.json();
      alert(data.success ? 'Password changed' : 'Error: ' + (data.error || 'unknown'));
    }

    function logout() {
      localStorage.removeItem('token');
      localStorage.removeItem('role');
      localStorage.removeItem('username');
      window.location.href = '/login';
    }

    fetchWorlds();
  </script>
</body>
</html>`,

  admin: `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Admin Panel</title>
<style>
  body { font-family: sans-serif; padding: 20px; }
  table { border-collapse: collapse; width: 100%; }
  th, td { border: 1px solid #ccc; padding: 8px; }
  .btn { padding: 6px 12px; cursor: pointer; }
  .btn-danger { background-color: #dc3545; color: white; }
  .password-hidden { font-family: monospace; color: #aaa; }
</style>
</head>
<body>
  <h2>Account Management</h2>
  <table id="accountsTable">
    <thead>
      <tr><th>Username</th><th>Role</th><th>Password</th><th>Actions</th></tr>
    </thead>
    <tbody></tbody>
  </table>
  <script>
    const token = localStorage.getItem('token');
    if(!token) location.href = '/login';

    async function loadAccounts() {
      const res = await fetch('/api/accounts', {headers: {Authorization: token}});
      const accounts = await res.json();
      const tbody = document.querySelector('#accountsTable tbody');
      tbody.innerHTML = '';
      accounts.forEach(acc => {
        const tr = document.createElement('tr');
        tr.innerHTML = \`
          <td>\${acc.username}</td>
          <td>\${acc.role}</td>
          <td><span class="password-hidden" id="pw-\${acc.username}">••••••••</span>
              <button onclick="togglePassword('\${acc.username}', '\${acc.password}')">View</button></td>
          <td>
            <button onclick="changePassword('\${acc.username}')">Change Password</button>
            <button class="btn btn-danger" onclick="deleteUser('\${acc.username}')">Delete</button>
          </td>
        \`;
        tbody.appendChild(tr);
      });
    }

    function togglePassword(username, pw) {
      const el = document.getElementById('pw-' + username);
      if(el.textContent === '••••••••') el.textContent = pw;
      else el.textContent = '••••••••';
    }

    async function changePassword(username) {
      const newPw = prompt('Enter new password for ' + username);
      if (!newPw) return alert('Cancelled');
      const res = await fetch('/api/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: token },
        body: JSON.stringify({ username, newPassword: newPw })
      });
      const data = await res.json();
      alert(data.success ? 'Password changed' : 'Error: ' + (data.error || 'unknown'));
    }

    async function deleteUser(username) {
      const confirmPw = prompt('Enter your admin password to confirm deletion of ' + username);
      const confirmDelete = confirm('Are you sure you want to delete ' + username + '? This action cannot be undone.');
      if(!confirmPw || !confirmDelete) return;
      const res = await fetch('/api/delete-user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: token },
        body: JSON.stringify({ username, confirmPassword: confirmPw, confirm: true })
      });
      const data = await res.json();
      if(data.success) {
        alert('Deleted ' + username);
        loadAccounts();
      } else {
        alert('Error: ' + (data.error || 'unknown'));
      }
    }

    loadAccounts();
  </script>
</body>
</html>`
};

async function parseJSON(req) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}

async function getUserFromToken(env, token) {
  if(!token) return null;
  const sessionRaw = await env.CODES.get(`session:${token}`);
  if(!sessionRaw) return null;
  const session = JSON.parse(sessionRaw);
  if(Date.now() > session.expires) return null;
  const userRaw = await env.CODES.get(`user:${session.username}`);
  if(!userRaw) return null;
  return {...JSON.parse(userRaw), username: session.username};
}

async function requireRole(env, req, roles) {
  const token = req.headers.get('Authorization');
  const user = await getUserFromToken(env, token);
  if(!user || !roles.includes(user.role)) return null;
  return user;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // Serve embedded HTML pages
    if(request.method === 'GET') {
      if(path === '/login') return new Response(htmlPages.login, {headers: {'Content-Type':'text/html'}});
      if(path === '/dashboard') return new Response(htmlPages.dashboard, {headers: {'Content-Type':'text/html'}});
      if(path === '/admin') return new Response(htmlPages.admin, {headers: {'Content-Type':'text/html'}});
    }

    // API: Login
    if(path === '/api/login' && request.method === 'POST') {
      const { username, password } = await parseJSON(request);
      if(!username || !password) return new Response(JSON.stringify({error:'Invalid'}), {status:401, headers: {'Content-Type':'application/json'}});
      const record = await env.CODES.get(`user:${username}`);
      if(!record) return new Response(JSON.stringify({error:'Invalid'}), {status:401, headers: {'Content-Type':'application/json'}});
      const user = JSON.parse(record);
      if(user.password !== password) return new Response(JSON.stringify({error:'Invalid'}), {status:401, headers: {'Content-Type':'application/json'}});
      const token = uuidv4();
      const expires = Date.now() + 86400000; // 1 day
      await env.CODES.put(`session:${token}`, JSON.stringify({username, expires}), {expirationTtl: 86400});
      return new Response(JSON.stringify({token, username, role: user.role}), {headers: {'Content-Type':'application/json'}});
    }

    // API: Signup - requires invite code or creation password
    if(path === '/api/signup' && request.method === 'POST') {
      const { username, password, inviteCode, creationPassword } = await parseJSON(request);
      if(!username || !password) return new Response(JSON.stringify({error:'Missing fields'}), {status:400, headers:{'Content-Type':'application/json'}});

      // Check if user exists
      if(await env.CODES.get(`user:${username}`)) {
        return new Response(JSON.stringify({error:'Username exists'}), {status:400, headers:{'Content-Type':'application/json'}});
      }

      // Check invite or creation password
      const storedCreationPass = await env.CODES.get('creationPassword') || 'pickled';
      let allowed = false;

      if(creationPassword && creationPassword === storedCreationPass) allowed = true;

      if(inviteCode) {
        const inviteRaw = await env.CODES.get(`invite:${inviteCode}`);
        if(inviteRaw) {
          const invite = JSON.parse(inviteRaw);
          if(invite.used) {
            return new Response(JSON.stringify({error:'Invite used'}), {status:403, headers:{'Content-Type':'application/json'}});
          }
          allowed = true;
          if(invite.oneTime) {
            invite.used = true;
            await env.CODES.put(`invite:${inviteCode}`, JSON.stringify(invite));
          }
        }
      }

      if(!allowed) return new Response(JSON.stringify({error:'Unauthorized'}), {status:401, headers:{'Content-Type':'application/json'}});

      const newUser = { password, role: 'user' };
      await env.CODES.put(`user:${username}`, JSON.stringify(newUser));
      return new Response(JSON.stringify({success:true}), {headers: {'Content-Type':'application/json'}});
    }

    // API: Get worlds - admin/manager see all, users see only their own
    if(path === '/api/worlds' && request.method === 'GET') {
      const token = request.headers.get('Authorization');
      const user = await getUserFromToken(env, token);
      if(!user) return new Response(JSON.stringify({error:'Unauthorized'}), {status:401, headers:{'Content-Type':'application/json'}});

      const list = await env.CODES.list({prefix:'world:'});
      const allWorlds = await Promise.all(list.keys.map(k => env.CODES.get(k.name).then(v => ({id:k.name.replace('world:',''), ...JSON.parse(v)}))));

      let filtered;
      if(user.role === 'admin' || user.role === 'manager') filtered = allWorlds;
      else filtered = allWorlds.filter(w => w.owner === user.username);

      return new Response(JSON.stringify(filtered), {headers: {'Content-Type':'application/json'}});
    }

    // API: Create world
    if(path === '/api/create-world' && request.method === 'POST') {
      const token = request.headers.get('Authorization');
      const user = await getUserFromToken(env, token);
      if(!user) return new Response(JSON.stringify({error:'Unauthorized'}), {status:401, headers:{'Content-Type':'application/json'}});

      const id = uuidv4();
      const defaultWorld = {
        id,
        owner: user.username,
        worldName: '',
        word1: '',
        word2: '',
        word3: '',
        word4: '',
        connectionId: ''
      };

      await env.CODES.put(`world:${id}`, JSON.stringify(defaultWorld));
      return new Response(JSON.stringify({success:true, id}), {headers: {'Content-Type':'application/json'}});
    }

    // API: Update world
    if(path === '/api/update-world' && request.method === 'POST') {
      const token = request.headers.get('Authorization');
      const user = await getUserFromToken(env, token);
      if(!user) return new Response(JSON.stringify({error:'Unauthorized'}), {status:401, headers:{'Content-Type':'application/json'}});

      const { id, data } = await parseJSON(request);
      if(!id || !data) return new Response(JSON.stringify({error:'Missing fields'}), {status:400, headers:{'Content-Type':'application/json'}});

      const existingRaw = await env.CODES.get(`world:${id}`);
      if(!existingRaw) return new Response(JSON.stringify({error:'World not found'}), {status:404, headers:{'Content-Type':'application/json'}});

      const existing = JSON.parse(existingRaw);

      if(user.role !== 'admin' && existing.owner !== user.username) {
        return new Response(JSON.stringify({error:'Forbidden'}), {status:403, headers:{'Content-Type':'application/json'}});
      }

      const updated = {...existing, ...data};
      await env.CODES.put(`world:${id}`, JSON.stringify(updated));
      return new Response(JSON.stringify({success:true}), {headers:{'Content-Type':'application/json'}});
    }

    // API: List accounts (admin only)
    if(path === '/api/accounts' && request.method === 'GET') {
      const user = await requireRole(env, request, ['admin']);
      if(!user) return new Response(JSON.stringify({error:'Unauthorized'}), {status:401, headers:{'Content-Type':'application/json'}});

      const list = await env.CODES.list({prefix:'user:'});
      const accounts = [];
      for(const key of list.keys) {
        const name = key.name.replace('user:', '');
        const dataRaw = await env.CODES.get(key.name);
        const data = JSON.parse(dataRaw);
        accounts.push({username: name, role: data.role, password: data.password});
      }
      return new Response(JSON.stringify(accounts), {headers:{'Content-Type':'application/json'}});
    }

    // API: Delete user (admin only, confirm with password)
    if(path === '/api/delete-user' && request.method === 'POST') {
      const user = await requireRole(env, request, ['admin']);
      if(!user) return new Response(JSON.stringify({error:'Unauthorized'}), {status:401, headers:{'Content-Type':'application/json'}});

      const { username, confirmPassword, confirm } = await parseJSON(request);
      if(!username || !confirmPassword || confirm !== true) return new Response(JSON.stringify({error:'Missing confirmation'}), {status:400, headers:{'Content-Type':'application/json'}});

      // Check admin password again
      const adminDataRaw = await env.CODES.get(`user:${user.username}`);
      const adminData = JSON.parse(adminDataRaw);
      if(adminData.password !== confirmPassword) return new Response(JSON.stringify({error:'Incorrect password'}), {status:403, headers:{'Content-Type':'application/json'}});

      await env.CODES.delete(`user:${username}`);

      // Delete user's worlds as well (optional)
      const listWorlds = await env.CODES.list({prefix:'world:'});
      for(const w of listWorlds.keys) {
        const worldRaw = await env.CODES.get(w.name);
        if(worldRaw) {
          const world = JSON.parse(worldRaw);
          if(world.owner === username) await env.CODES.delete(w.name);
        }
      }

      return new Response(JSON.stringify({success:true}), {headers:{'Content-Type':'application/json'}});
    }

    // API: Change password (admin can change any, user can change own)
    if(path === '/api/change-password' && request.method === 'POST') {
      const user = await getUserFromToken(env, request.headers.get('Authorization'));
      if(!user) return new Response(JSON.stringify({error:'Unauthorized'}), {status:401, headers:{'Content-Type':'application/json'}});

      const { username, newPassword } = await parseJSON(request);
      if(!username || !newPassword) return new Response(JSON.stringify({error:'Missing fields'}), {status:400, headers:{'Content-Type':'application/json'}});

      // Only admin or self can change
      if(user.role !== 'admin' && user.username !== username) {
        return new Response(JSON.stringify({error:'Forbidden'}), {status:403, headers:{'Content-Type':'application/json'}});
      }

      const targetRaw = await env.CODES.get(`user:${username}`);
      if(!targetRaw) return new Response(JSON.stringify({error:'User not found'}), {status:404, headers:{'Content-Type':'application/json'}});

      const target = JSON.parse(targetRaw);
      target.password = newPassword;
      await env.CODES.put(`user:${username}`, JSON.stringify(target));

      return new Response(JSON.stringify({success:true}), {headers:{'Content-Type':'application/json'}});
    }

    // 404 fallback
    return new Response('Not found', {status:404});
  }
};
