// worker.js

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" /><meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Login</title>
  <style>
    body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #282c34; color: white; }
    form { background: #1e1e2f; padding: 2em; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.5); display: flex; flex-direction: column; gap: 1em; width: 300px; }
    input, button { padding: 0.5em; border-radius: 5px; border: none; }
    button { background: #61dafb; color: black; cursor: pointer; }
    button:hover { background: #21a1f1; }
  </style>
</head>
<body>
  <form id="loginForm">
    <h2>Login / Signup</h2>
    <input type="text" id="username" placeholder="Username" required />
    <input type="password" id="password" placeholder="Password" required />
    <input type="text" id="invite" placeholder="Invite Code (optional)" />
    <button type="submit">Submit</button>
  </form>
  <script>
    document.getElementById('loginForm').addEventListener('submit', async e => {
      e.preventDefault();
      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value.trim();
      const invite = document.getElementById('invite').value.trim();
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, invite }),
      });
      const data = await res.json();
      if(data.token) {
        localStorage.setItem('token', data.token);
        window.location.href = '/dashboard.html';
      } else {
        alert(data.error || 'Login failed');
      }
    });
  </script>
</body>
</html>`;

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" /><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Dashboard</title>
<style>
  body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f4f4f4; }
  .sidebar { position: fixed; left: 0; top: 0; width: 250px; height: 100vh; background: #333; color: #fff; overflow-y: auto; padding: 10px; display: none; }
  .sidebar h2 { margin-top: 0; }
  .sidebar .user { margin-bottom: 10px; padding: 5px; border-bottom: 1px solid #555; }
  .sidebar .user .view-password { display: none; color: #ccc; }
  .main { margin-left: 0; padding: 20px; transition: margin-left 0.3s ease; }
  .main.with-sidebar { margin-left: 260px; }
  table { width: 100%; border-collapse: collapse; background: white; }
  th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
  th { background-color: #f2f2f2; }
  .footer-buttons { position: fixed; right: 10px; bottom: 10px; }
  input[type=text], input[type=password] { width: 100%; box-sizing: border-box; }
  button { cursor: pointer; }
</style>
</head>
<body>
  <div class="sidebar" id="adminSidebar">
    <h2>Admin Panel</h2>
    <div id="userList"></div>
  </div>
  <div class="main" id="mainContent">
    <h1>World Code Manager</h1>
    <div id="worldList"></div>

    <h3>Create New World Code</h3>
    <form id="createForm">
      <input type="text" id="worldName" placeholder="World Name" required /><br />
      <input type="text" id="word1" placeholder="Word 1" required /><br />
      <input type="text" id="word2" placeholder="Word 2" required /><br />
      <input type="text" id="word3" placeholder="Word 3" required /><br />
      <input type="text" id="word4" placeholder="Word 4" required /><br />
      <input type="text" id="connectionId" placeholder="Connection ID (optional)" /><br />
      <button type="submit">Create Code</button>
    </form>

    <h3>Change Password</h3>
    <form id="changePasswordForm">
      <input type="password" id="oldPassword" placeholder="Old Password" required /><br />
      <input type="password" id="newPassword" placeholder="New Password" required /><br />
      <button type="submit">Change Password</button>
    </form>

    <h3>Invites</h3>
    <div id="inviteList"></div>
    <form id="inviteForm">
      <input type="text" id="inviteCode" placeholder="Invite Code" required />
      <label><input type="checkbox" id="multiUse" /> Multi-use (unlimited)</label>
      <button type="submit">Create Invite</button>
    </form>
  </div>

  <div class="footer-buttons">
    <button onclick="logout()">Logout</button>
  </div>

<script>
  const token = localStorage.getItem('token');
  if(!token) location.href = '/login.html';

  async function fetchDashboard() {
    const res = await fetch('/api/dashboard', { headers: { 'Authorization': token } });
    if(!res.ok) return logout();
    const data = await res.json();
    renderDashboard(data);
  }

  function renderDashboard(data) {
    const worldList = document.getElementById('worldList');
    worldList.innerHTML = '';
    if(!data.codes) data.codes = [];
    data.codes.forEach(code => {
      const div = document.createElement('div');
      div.innerHTML = \`
        <strong>\${code.owner}</strong> - 
        <input type="text" data-id="\${code.id}" data-field="name" value="\${code.name}" placeholder="World Name" />
        <input type="text" data-id="\${code.id}" data-field="word1" value="\${code.word1}" placeholder="Word 1" size="5" />
        <input type="text" data-id="\${code.id}" data-field="word2" value="\${code.word2}" placeholder="Word 2" size="5" />
        <input type="text" data-id="\${code.id}" data-field="word3" value="\${code.word3}" placeholder="Word 3" size="5" />
        <input type="text" data-id="\${code.id}" data-field="word4" value="\${code.word4}" placeholder="Word 4" size="5" />
        <input type="text" data-id="\${code.id}" data-field="connectionId" value="\${code.connectionId||''}" placeholder="Connection ID" size="10" />
        <button onclick="save('\${code.id}')">Save</button>
      \`;
      worldList.appendChild(div);
    });

    // Admin sidebar user list
    if(data.role === 'admin') {
      document.getElementById('adminSidebar').style.display = 'block';
      document.getElementById('mainContent').classList.add('with-sidebar');
      const userList = document.getElementById('userList');
      userList.innerHTML = '';
      if(data.users) {
        data.users.forEach(u => {
          const userDiv = document.createElement('div');
          userDiv.className = 'user';
          userDiv.innerHTML = \`
            <strong>\${u.username}</strong><br>
            <button onclick="togglePass(this)">View Password</button>
            <span class="view-password" style="display:none">\${u.password || '[hidden]'}</span><br>
            <input type="password" id="verify_\${u.username}" placeholder="Re-enter your password" /><br>
            <label><input type="checkbox" id="confirm_\${u.username}" /> Confirm</label><br>
            <button onclick="deleteUser('\${u.username}')">Delete User</button>
          \`;
          userList.appendChild(userDiv);
        });
      }
    } else {
      document.getElementById('adminSidebar').style.display = 'none';
      document.getElementById('mainContent').classList.remove('with-sidebar');
    }

    // Invites list
    const inviteList = document.getElementById('inviteList');
    inviteList.innerHTML = '';
    if(data.invites) {
      data.invites.forEach(inv => {
        const invDiv = document.createElement('div');
        invDiv.textContent = \`Code: \${inv.code} | Multi-use: \${inv.multiUse} | Created by: \${inv.createdBy}\`;
        if(data.role === 'admin' || (data.role === 'manager' && inv.createdBy === data.username)) {
          const delBtn = document.createElement('button');
          delBtn.textContent = 'Delete';
          delBtn.onclick = () => deleteInvite(inv.code);
          invDiv.appendChild(delBtn);
        }
        inviteList.appendChild(invDiv);
      });
    }
  }

  function togglePass(btn) {
    const span = btn.nextElementSibling;
    span.style.display = span.style.display === 'inline' ? 'none' : 'inline';
  }

  async function save(id) {
    const inputs = document.querySelectorAll(\`[data-id="\${id}"]\`);
    const body = {};
    inputs.forEach(i => body[i.dataset.field] = i.value);
    const res = await fetch('/api/world/' + id, {
      method: 'PUT',
      headers: { 'Authorization': token, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if(data.success) alert('Saved!');
    else alert(data.error || 'Error saving');
    fetchDashboard();
  }

  async function deleteUser(username) {
    const confirmBox = document.getElementById('confirm_' + username);
    const passInput = document.getElementById('verify_' + username);
    if(!confirmBox.checked || !passInput.value) return alert('Please confirm and enter your password');
    const res = await fetch('/api/admin/delete-user', {
      method: 'POST',
      headers: { 'Authorization': token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: passInput.value })
    });
    if(res.ok) fetchDashboard();
    else alert('Failed to delete user');
  }

  async function deleteInvite(code) {
    const res = await fetch('/api/invite/' + code, {
      method: 'DELETE',
      headers: { 'Authorization': token }
    });
    if(res.ok) fetchDashboard();
    else alert('Failed to delete invite');
  }

  async function logout() {
    localStorage.removeItem('token');
    window.location.href = '/login.html';
  }

  document.getElementById('createForm').addEventListener('submit', async e => {
    e.preventDefault();
    const body = {
      name: document.getElementById('worldName').value,
      word1: document.getElementById('word1').value,
      word2: document.getElementById('word2').value,
      word3: document.getElementById('word3').value,
      word4: document.getElementById('word4').value,
      connectionId: document.getElementById('connectionId').value
    };
    const res = await fetch('/api/world', {
      method: 'POST',
      headers: { 'Authorization': token, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if(data.success) {
      alert('World code created!');
      e.target.reset();
      fetchDashboard();
    } else {
      alert(data.error || 'Failed to create code');
    }
  });

  document.getElementById('changePasswordForm').addEventListener('submit', async e => {
    e.preventDefault();
    const body = {
      oldPassword: document.getElementById('oldPassword').value,
      newPassword: document.getElementById('newPassword').value
    };
    const res = await fetch('/api/change-password', {
      method: 'POST',
      headers: { 'Authorization': token, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if(data.success) {
      alert('Password changed!');
      e.target.reset();
    } else {
      alert(data.error || 'Failed to change password');
    }
  });

  document.getElementById('inviteForm').addEventListener('submit', async e => {
    e.preventDefault();
    const body = {
      code: document.getElementById('inviteCode').value.trim(),
      multiUse: document.getElementById('multiUse').checked
    };
    const res = await fetch('/api/invite', {
      method: 'POST',
      headers: { 'Authorization': token, 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();
    if(data.success) {
      alert('Invite created!');
      e.target.reset();
      fetchDashboard();
    } else {
      alert(data.error || 'Failed to create invite');
    }
  });

  fetchDashboard();
</script>
</body>
</html>`;

import { createHash } from 'crypto';

// --- Helper functions and constants ---

// To generate UUIDs, a simple function (since you can't import 'uuid' in Workers)
function generateUUID() {
  // RFC4122 version 4 UUID from https://stackoverflow.com/a/2117523
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (crypto.getRandomValues(new Uint8Array(1))[0] & 0xf) >> 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

// Password hashing using SHA-256 (simple)
// Returns hex string
async function hashPassword(password) {
  const data = new TextEncoder().encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(storedHash, password) {
  const passwordHash = await hashPassword(password);
  return storedHash === passwordHash;
}

function unauthorizedResponse() {
  return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
}

function badRequestResponse(msg = 'Bad Request') {
  return new Response(JSON.stringify({ error: msg }), { status: 400, headers: { 'Content-Type': 'application/json' } });
}

function jsonResponse(data) {
  return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
}

function extractToken(request) {
  const auth = request.headers.get('Authorization');
  if (!auth) return null;
  const parts = auth.split(' ');
  if (parts.length !== 2) return null;
  if (parts[0] !== 'Bearer') return null;
  return parts[1];
}

function generateJWT(payload, secret) {
  // Simple JWT implementation (header.payload.signature)
  // For demo purposes only; in production use a proper JWT library or Cloudflare Access.
  // Here we use base64url encoding + HMAC SHA256 signature.
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = btoa(JSON.stringify(payload));

  // HMAC SHA256
  const keyData = new TextEncoder().encode(secret);
  const msgData = new TextEncoder().encode(`${header}.${body}`);
  // crypto.subtle API is async, so this function needs to be async.
  // So let's do it sync-like below by making generateJWT async and awaiting it.

  // We'll re-implement generateJWT as async below.
  return null; // placeholder
}

async function signJWT(payload, secret) {
  function base64url(source) {
    return btoa(source)
      .replace(/=+$/, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
  }
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerBase64 = base64url(JSON.stringify(header));
  const payloadBase64 = base64url(JSON.stringify(payload));
  const data = new TextEncoder().encode(headerBase64 + '.' + payloadBase64);
  const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(headerBase64 + '.' + payloadBase64));
  const signatureBase64 = base64url(String.fromCharCode(...new Uint8Array(signatureBuffer)));
  return `${headerBase64}.${payloadBase64}.${signatureBase64}`;
}

async function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [header64, payload64, signature] = parts;

  function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return atob(str);
  }

  function base64urlEncode(str) {
    return btoa(str).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  }

  const payload = JSON.parse(base64urlDecode(payload64));
  const expectedSig = await signJWT(payload, secret);
  if (token === expectedSig) return payload;
  return null;
}

async function parseRequestBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

// Main event listener
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request, event));
});

async function handleRequest(request, event) {
  const url = new URL(request.url);
  const path = url.pathname;

  // Serve HTML pages
  if (request.method === 'GET') {
    if (path === '/' || path === '/login.html') {
      return new Response(loginHTML, { headers: { 'Content-Type': 'text/html' } });
    }
    if (path === '/dashboard.html') {
      return new Response(dashboardHTML, { headers: { 'Content-Type': 'text/html' } });
    }
  }

  // API routes
  if (path.startsWith('/api/')) {
    const token = extractToken(request);
    const body = await parseRequestBody(request);

    if (path === '/api/login' && request.method === 'POST') {
      // Login or signup
      if (!body || !body.username || !body.password) {
        return badRequestResponse('Username and password required');
      }
      return handleLogin(body.username, body.password, body.invite);
    }

    // All other API endpoints require auth
    if (!token) return unauthorizedResponse();
    const user = await verifyToken(token);
    if (!user) return unauthorizedResponse();

    if (path === '/api/dashboard' && request.method === 'GET') {
      return handleDashboard(user);
    }

    if (path === '/api/world' && request.method === 'POST') {
      return handleCreateWorldCode(user, body);
    }

    if (path.startsWith('/api/world/') && request.method === 'PUT') {
      const id = path.split('/')[3];
      if (!id) return badRequestResponse('ID required');
      return handleUpdateWorldCode(user, id, body);
    }

    if (path === '/api/change-password' && request.method === 'POST') {
      return handleChangePassword(user, body);
    }

    if (path === '/api/invite' && request.method === 'POST') {
      return handleCreateInvite(user, body);
    }

    if (path.startsWith('/api/invite/') && request.method === 'DELETE') {
      const code = path.split('/')[3];
      if (!code) return badRequestResponse('Invite code required');
      return handleDeleteInvite(user, code);
    }

    if (path === '/api/admin/delete-user' && request.method === 'POST') {
      return handleDeleteUser(user, body);
    }
  }

  return new Response('Not found', { status: 404 });
}

// KV binding
const CODES = CODES; // from wrangler.toml binding

// Main data keys and structures:

// User object:
// {
//   username: string,
//   passwordHash: string,
//   role: "admin"|"manager"|"user",
//   inviteCreatedCodes: [string], // invite codes created by manager
// }

// World Code object:
// {
//   id: uuid,
//   owner: username,
//   name, word1, word2, word3, word4, connectionId
// }

// Invite object:
// {
//   code: string,
//   multiUse: boolean,
//   usedCount: number,
//   maxUses: number|null,
//   createdBy: username,
//   createdAt: timestamp
// }

// Signup password (default 'pickled') stored as "signupPassword" in KV

// TOKEN expiration 1 day (86400 seconds)

async function getUser(username) {
  const data = await CODES.get(`user_${username}`);
  if (!data) return null;
  return JSON.parse(data);
}

async function putUser(user) {
  await CODES.put(`user_${user.username}`, JSON.stringify(user));
}

async function deleteUserByName(username) {
  await CODES.delete(`user_${username}`);
}

async function getAllUsers() {
  // No native listing in KV, but you can store a separate index of usernames
  let users = await CODES.get('userIndex');
  if (!users) return [];
  return JSON.parse(users);
}

async function addUserToIndex(username) {
  let users = await getAllUsers();
  if (!users.includes(username)) {
    users.push(username);
    await CODES.put('userIndex', JSON.stringify(users));
  }
}

async function removeUserFromIndex(username) {
  let users = await getAllUsers();
  users = users.filter(u => u !== username);
  await CODES.put('userIndex', JSON.stringify(users));
}

async function getWorldCode(id) {
  const data = await CODES.get(`world_${id}`);
  if (!data) return null;
  return JSON.parse(data);
}

async function putWorldCode(code) {
  await CODES.put(`world_${code.id}`, JSON.stringify(code));
}

async function getAllWorldCodes() {
  let codes = await CODES.get('worldIndex');
  if (!codes) return [];
  return JSON.parse(codes);
}

async function addWorldCodeToIndex(id) {
  let codes = await getAllWorldCodes();
  if (!codes.includes(id)) {
    codes.push(id);
    await CODES.put('worldIndex', JSON.stringify(codes));
  }
}

async function removeWorldCodeFromIndex(id) {
  let codes = await getAllWorldCodes();
  codes = codes.filter(c => c !== id);
  await CODES.put('worldIndex', JSON.stringify(codes));
}

async function getInvite(code) {
  const data = await CODES.get(`invite_${code}`);
  if (!data) return null;
  return JSON.parse(data);
}

async function putInvite(invite) {
  await CODES.put(`invite_${invite.code}`, JSON.stringify(invite));
}

async function deleteInvite(code) {
  await CODES.delete(`invite_${code}`);
}

async function getAllInvites() {
  let invites = await CODES.get('inviteIndex');
  if (!invites) return [];
  return JSON.parse(invites);
}

async function addInviteToIndex(code) {
  let invites = await getAllInvites();
  if (!invites.includes(code)) {
    invites.push(code);
    await CODES.put('inviteIndex', JSON.stringify(invites));
  }
}

async function removeInviteFromIndex(code) {
  let invites = await getAllInvites();
  invites = invites.filter(c => c !== code);
  await CODES.put('inviteIndex', JSON.stringify(invites));
}

async function getSignupPassword() {
  const val = await CODES.get('signupPassword');
  if (!val) return 'pickled';
  return val;
}

async function setSignupPassword(pw) {
  await CODES.put('signupPassword', pw);
}

async function verifyToken(token) {
  try {
    const payload = await verifyJWT(token, TOKEN_SECRET);
    if (!payload) return null;
    const user = await getUser(payload.username);
    if (!user) return null;
    // check token expiry (1 day)
    if (Date.now() > payload.exp) return null;
    return user;
  } catch {
    return null;
  }
}

async function handleLogin(username, password, inviteCode) {
  username = username.toLowerCase();
  const user = await getUser(username);

  if (user) {
    // user exists, verify password
    const ok = await verifyPassword(user.passwordHash, password);
    if (!ok) return jsonResponse({ error: 'Invalid username or password' }, { status: 401 });
    // return token
    const token = await signJWT({
      username: user.username,
      role: user.role,
      exp: Date.now() + 86400 * 1000,
    }, TOKEN_SECRET);
    return jsonResponse({ token });
  } else {
    // Signup flow: require invite OR signupPassword
    const signupPw = await getSignupPassword();
    if ((!inviteCode && password !== signupPw) && !inviteCode) {
      return jsonResponse({ error: 'Signup requires invite code or correct signup password' }, { status: 401 });
    }
    // if inviteCode provided, check invite
    if (inviteCode) {
      const invite = await getInvite(inviteCode);
      if (!invite) return jsonResponse({ error: 'Invalid invite code' }, { status: 401 });
      if (!invite.multiUse && invite.usedCount >= 1) return jsonResponse({ error: 'Invite code already used' }, { status: 401 });
    }

    // create new user with default role 'user'
    const passwordHash = await hashPassword(password);
    const newUser = {
      username,
      passwordHash,
      role: 'user',
      inviteCreatedCodes: [],
    };
    await putUser(newUser);
    await addUserToIndex(username);

    if (inviteCode) {
      const invite = await getInvite(inviteCode);
      invite.usedCount = (invite.usedCount || 0) + 1;
      if (!invite.multiUse && invite.usedCount >= 1) {
        // remove invite from index & KV
        await removeInviteFromIndex(inviteCode);
        await deleteInvite(inviteCode);
      } else {
        await putInvite(invite);
      }
    }

    const token = await signJWT({
      username: newUser.username,
      role: newUser.role,
      exp: Date.now() + 86400 * 1000,
    }, TOKEN_SECRET);
    return jsonResponse({ token });
  }
}

async function handleDashboard(user) {
  // Load codes user can see/edit based on role
  const allUsers = await getAllUsers();
  const allCodesIds = await getAllWorldCodes();
  const allCodes = [];

  for (const id of allCodesIds) {
    const code = await getWorldCode(id);
    if (!code) continue;
    allCodes.push(code);
  }

  // Invites
  const allInvitesIds = await getAllInvites();
  const allInvites = [];
  for (const code of allInvitesIds) {
    const inv = await getInvite(code);
    if (inv) allInvites.push(inv);
  }

  // Build response
  // admin: all codes, all users, all invites
  // manager: all codes, invites they created, users hidden
  // user: only codes they own, invites hidden

  let codesToReturn = [];
  let invitesToReturn = [];
  let usersToReturn = [];

  if (user.role === 'admin') {
    codesToReturn = allCodes;
    invitesToReturn = allInvites;
    usersToReturn = allUsers.map(u => {
      const usr = getUser(u);
      return usr;
    });
    // await Promise.all for allUsers to resolve all getUser
    usersToReturn = [];
    for(const u of allUsers) {
      const usr = await getUser(u);
      if(usr) usersToReturn.push({ username: usr.username, password: '[hidden]' });
    }
  } else if (user.role === 'manager') {
    codesToReturn = allCodes;
    invitesToReturn = allInvites.filter(inv => inv.createdBy === user.username);
    usersToReturn = [];
  } else {
    codesToReturn = allCodes.filter(c => c.owner === user.username);
  }

  return jsonResponse({
    username: user.username,
    role: user.role,
    codes: codesToReturn,
    invites: invitesToReturn,
    users: usersToReturn,
  });
}

async function handleCreateWorldCode(user, body) {
  if (!body || !body.name || !body.word1 || !body.word2 || !body.word3 || !body.word4) {
    return badRequestResponse('Missing fields');
  }

  const id = generateUUID();
  const newCode = {
    id,
    owner: user.username,
    name: body.name,
    word1: body.word1,
    word2: body.word2,
    word3: body.word3,
    word4: body.word4,
    connectionId: body.connectionId || '',
  };

  await putWorldCode(newCode);
  await addWorldCodeToIndex(id);

  return jsonResponse({ success: true, id });
}

async function handleUpdateWorldCode(user, id, body) {
  const code = await getWorldCode(id);
  if (!code) return badRequestResponse('World code not found');

  // Check if user can edit
  if (user.role !== 'admin' && user.role !== 'manager' && code.owner !== user.username) {
    return unauthorizedResponse();
  }

  // Manager can only edit their own codes
  if (user.role === 'manager' && code.owner !== user.username) {
    return unauthorizedResponse();
  }

  // Update fields
  ['name', 'word1', 'word2', 'word3', 'word4', 'connectionId'].forEach(field => {
    if (body[field] !== undefined) code[field] = body[field];
  });

  await putWorldCode(code);
  return jsonResponse({ success: true });
}

async function handleChangePassword(user, body) {
  if (!body || !body.oldPassword || !body.newPassword) return badRequestResponse('Missing fields');
  const ok = await verifyPassword(user.passwordHash, body.oldPassword);
  if (!ok) return badRequestResponse('Old password incorrect');

  const newHash = await hashPassword(body.newPassword);
  user.passwordHash = newHash;
  await putUser(user);

  return jsonResponse({ success: true });
}

async function handleCreateInvite(user, body) {
  if (!body || !body.code) return badRequestResponse('Invite code required');

  // Only admin or manager can create invites
  if (user.role !== 'admin' && user.role !== 'manager') return unauthorizedResponse();

  const existing = await getInvite(body.code);
  if (existing) return badRequestResponse('Invite code already exists');

  const invite = {
    code: body.code,
    multiUse: !!body.multiUse,
    usedCount: 0,
    maxUses: body.multiUse ? null : 1,
    createdBy: user.username,
    createdAt: Date.now(),
  };

  await putInvite(invite);
  await addInviteToIndex(invite.code);

  return jsonResponse({ success: true });
}

async function handleDeleteInvite(user, code) {
  const invite = await getInvite(code);
  if (!invite) return badRequestResponse('Invite not found');

  if (user.role !== 'admin' && !(user.role === 'manager' && invite.createdBy === user.username)) {
    return unauthorizedResponse();
  }

  await deleteInvite(code);
  await removeInviteFromIndex(code);

  return jsonResponse({ success: true });
}

async function handleDeleteUser(user, body) {
  if (!body || !body.username || !body.password) return badRequestResponse('Missing fields');

  // Only admin can delete users
  if (user.role !== 'admin') return unauthorizedResponse();

  const passwordOk = await verifyPassword(user.passwordHash, body.password);
  if (!passwordOk) return badRequestResponse('Your password incorrect');

  if (body.username === user.username) return badRequestResponse('Cannot delete yourself');

  await deleteUserByName(body.username);
  await removeUserFromIndex(body.username);

  // Also delete their codes
  const allCodes = await getAllWorldCodes();
  for (const id of allCodes) {
    const code = await getWorldCode(id);
    if (code && code.owner === body.username) {
      await removeWorldCodeFromIndex(id);
      await CODES.delete(`world_${id}`);
    }
  }

  return jsonResponse({ success: true });
}
