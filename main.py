<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>EXE Account Admin</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Syne:wght@700;800&family=Outfit:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0a0a0a; color: #e8e8e8; font-family: 'Outfit', sans-serif; padding: 32px; }
  h1 { font-family: 'Syne', sans-serif; font-weight: 800; letter-spacing: 4px; font-size: 22px; margin-bottom: 4px; }
  .sub { font-family: 'DM Mono', monospace; font-size: 11px; color: rgba(232,232,232,0.4); letter-spacing: 1px; margin-bottom: 24px; }
  input { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 9px 12px; font-family: 'DM Mono', monospace; font-size: 12px; border-radius: 6px; outline: none; }
  input:focus { border-color: rgba(255,255,255,0.3); }
  button { background: rgba(255,255,255,0.08); border: 1px solid rgba(255,255,255,0.2); color: #fff; padding: 9px 16px; font-family: 'Syne', sans-serif; font-weight: 700; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; border-radius: 6px; cursor: pointer; }
  button:hover { background: rgba(255,255,255,0.14); }
  button.danger { border-color: rgba(255,59,59,0.4); color: #ff6b6b; background: rgba(255,59,59,0.06); }
  button.danger:hover { background: rgba(255,59,59,0.14); }
  button.warn { border-color: rgba(240,192,64,0.4); color: #f0c040; background: rgba(240,192,64,0.06); }
  button.warn:hover { background: rgba(240,192,64,0.14); }
  #login-box, #panel { max-width: 1100px; }
  #login-box { display: flex; flex-direction: column; gap: 10px; max-width: 380px; }
  #panel { display: none; }
  table { width: 100%; border-collapse: collapse; margin-top: 20px; }
  th { text-align: left; font-family: 'DM Mono', monospace; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; color: rgba(232,232,232,0.4); padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.12); }
  td { padding: 12px; border-bottom: 1px solid rgba(255,255,255,0.06); font-size: 13px; vertical-align: middle; }
  tr:hover td { background: rgba(255,255,255,0.02); }
  .badge { font-family: 'DM Mono', monospace; font-size: 10px; letter-spacing: 1px; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; }
  .badge.active { background: rgba(120,220,140,0.12); color: #7ee89a; }
  .badge.held { background: rgba(240,192,64,0.12); color: #f0c040; }
  .badge.terminated { background: rgba(255,59,59,0.12); color: #ff6b6b; }
  .badge.admin { background: rgba(255,255,255,0.1); color: #fff; margin-left: 6px; }
  .actions { display: flex; gap: 6px; }
  #err { color: #ff6b6b; font-family: 'DM Mono', monospace; font-size: 11px; }
  #api-origin-row { display: flex; gap: 8px; align-items: center; margin-bottom: 20px; }
  #api-origin-row input { flex: 1; }
</style>
</head>
<body>

<h1>EXE ACCOUNT ADMIN</h1>
<div class="sub">Local management panel — not for public hosting</div>

<div id="login-box">
  <input id="api-origin" placeholder="API URL, e.g. https://exe-accounts-xyz.onrender.com">
  <input id="login-email" placeholder="Admin email">
  <input id="login-password" type="password" placeholder="Password">
  <button onclick="doLogin()">Log In</button>
  <div id="err"></div>
</div>

<div id="panel">
  <div id="api-origin-row">
    <span class="sub" style="margin:0;">API:</span>
    <input id="api-origin-display" disabled>
    <button onclick="doLogout()">Log Out</button>
  </div>
  <table>
    <thead>
      <tr><th>Email</th><th>Name</th><th>Status</th><th>Verified</th><th>Joined</th><th>Actions</th></tr>
    </thead>
    <tbody id="user-rows"></tbody>
  </table>
</div>

<script>
let apiOrigin = localStorage.getItem('exeAdminApiOrigin') || '';
let accessToken = null;

document.getElementById('api-origin').value = apiOrigin;

async function doLogin() {
  apiOrigin = document.getElementById('api-origin').value.trim().replace(/\/$/, '');
  const email = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl = document.getElementById('err');
  errEl.textContent = '';

  if (!apiOrigin || !email || !password) {
    errEl.textContent = 'Fill in the API URL, email, and password.';
    return;
  }

  try {
    const res = await fetch(apiOrigin + '/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, app: 'exe-admin-panel' }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || 'Login failed');
    if (!data.user.is_admin) throw new Error('This account is not an admin');

    accessToken = data.access_token;
    localStorage.setItem('exeAdminApiOrigin', apiOrigin);
    document.getElementById('api-origin-display').value = apiOrigin;
    document.getElementById('login-box').style.display = 'none';
    document.getElementById('panel').style.display = 'block';
    loadUsers();
  } catch (e) {
    errEl.textContent = e.message;
  }
}

function doLogout() {
  accessToken = null;
  document.getElementById('panel').style.display = 'none';
  document.getElementById('login-box').style.display = 'flex';
}

async function api(method, path, body) {
  const res = await fetch(apiOrigin + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + accessToken,
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || res.statusText);
  return data;
}

async function loadUsers() {
  const rows = document.getElementById('user-rows');
  rows.innerHTML = '<tr><td colspan="6">Loading…</td></tr>';
  try {
    const users = await api('GET', '/admin/users');
    rows.innerHTML = '';
    users.forEach(u => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${escapeHtml(u.email)}</td>
        <td>${escapeHtml(u.display_name)}${u.is_admin ? '<span class="badge admin">Admin</span>' : ''}</td>
        <td><span class="badge ${u.status}">${u.status}</span></td>
        <td>${u.email_verified ? 'Yes' : 'No'}</td>
        <td>${new Date(u.created_at).toLocaleDateString()}</td>
        <td class="actions"></td>
      `;
      const actionsCell = tr.querySelector('.actions');

      if (u.status !== 'held') {
        actionsCell.appendChild(makeBtn('Hold', 'warn', () => act(u.id, 'hold')));
      } else {
        actionsCell.appendChild(makeBtn('Unhold', '', () => act(u.id, 'unhold')));
      }
      if (u.status !== 'terminated') {
        actionsCell.appendChild(makeBtn('Terminate', 'danger', () => act(u.id, 'terminate')));
      }
      actionsCell.appendChild(makeBtn('Delete', 'danger', () => deleteUser(u.id, u.email)));

      rows.appendChild(tr);
    });
  } catch (e) {
    rows.innerHTML = `<tr><td colspan="6" style="color:#ff6b6b;">${escapeHtml(e.message)}</td></tr>`;
  }
}

function makeBtn(label, cls, onClick) {
  const b = document.createElement('button');
  b.textContent = label;
  if (cls) b.className = cls;
  b.onclick = onClick;
  return b;
}

async function act(userId, action) {
  try {
    await api('POST', `/admin/users/${userId}/${action}`);
    loadUsers();
  } catch (e) {
    alert(e.message);
  }
}

async function deleteUser(userId, email) {
  if (!confirm(`Permanently delete ${email}? This can't be undone.`)) return;
  try {
    await api('DELETE', `/admin/users/${userId}`);
    loadUsers();
  } catch (e) {
    alert(e.message);
  }
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s ?? '';
  return d.innerHTML;
}
</script>
</body>
</html>
