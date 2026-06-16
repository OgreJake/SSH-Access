// Thin client over the management API. Authentication is cookie-based
// (ADR-008): the break-glass login sets an httpOnly session cookie, and the
// reverse proxy injects OIDC identity — both travel automatically with the
// request, so the client sends no Authorization header. `credentials` ensures
// the cookie is included.

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(method, path, body) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }
  if (!res.ok) {
    throw new ApiError((data && data.error) || res.statusText || 'request failed', res.status);
  }
  return data;
}

// requestText returns the raw response body (for file downloads like recordings).
async function requestText(method, path) {
  const res = await fetch(path, { method, credentials: 'same-origin' });
  const text = await res.text();
  if (!res.ok) {
    let msg = res.statusText || 'request failed';
    try {
      const j = JSON.parse(text);
      if (j && j.error) msg = j.error;
    } catch {
      /* not JSON */
    }
    throw new ApiError(msg, res.status);
  }
  return text;
}

export const api = {
  // Auth (ADR-008 Phase A).
  whoami: () => request('GET', '/api/v1/auth/whoami'),
  localLogin: (username, password) =>
    request('POST', '/api/v1/auth/local/login', { username, password }),
  localLogout: () => request('POST', '/api/v1/auth/local/logout'),

  listUsers: () => request('GET', '/api/v1/users'),
  createUser: (b) => request('POST', '/api/v1/users', b),
  updateUser: (id, b) => request('PATCH', `/api/v1/users/${id}`, b),
  setUserStatus: (id, status) => request('PATCH', `/api/v1/users/${id}`, { status }),
  deleteUser: (id) => request('DELETE', `/api/v1/users/${id}`),
  addUserKey: (id, public_key, comment) =>
    request('POST', `/api/v1/users/${id}/keys`, { public_key, comment }),

  listServers: () => request('GET', '/api/v1/servers'),
  createServer: (b) => request('POST', '/api/v1/servers', b),
  updateServer: (id, b) => request('PATCH', `/api/v1/servers/${id}`, b),
  deleteServer: (id) => request('DELETE', `/api/v1/servers/${id}`),

  listGrants: () => request('GET', '/api/v1/grants'),
  createGrant: (b) => request('POST', '/api/v1/grants', b),
  updateGrant: (id, b) => request('PATCH', `/api/v1/grants/${id}`, b),
  deleteGrant: (id) => request('DELETE', `/api/v1/grants/${id}`),
  recertifyGrant: (id) => request('POST', `/api/v1/grants/${id}/recertify`),

  listUserGroups: () => request('GET', '/api/v1/user-groups'),
  createUserGroup: (name) => request('POST', '/api/v1/user-groups', { name }),
  addUserGroupMember: (id, user_id) =>
    request('POST', `/api/v1/user-groups/${id}/members`, { user_id }),

  listServerGroups: () => request('GET', '/api/v1/server-groups'),
  createServerGroup: (name) => request('POST', '/api/v1/server-groups', { name }),
  addServerGroupMember: (id, server_id) =>
    request('POST', `/api/v1/server-groups/${id}/members`, { server_id }),

  listSessions: () => request('GET', '/api/v1/sessions'),
  terminateSession: (id) => request('POST', `/api/v1/sessions/${id}/terminate`),
  downloadRecording: (id) => requestText('GET', `/api/v1/sessions/${id}/recording`),
  listAudit: () => request('GET', '/api/v1/audit'),
  exportAudit: () => request('GET', '/api/v1/audit/export'),
  verifyAudit: () => request('GET', '/api/v1/audit/verify'),

  // SSH browser-SSO approval (ADR-021).
  sshLoginInfo: (code) => request('GET', '/api/v1/ssh-login?code=' + encodeURIComponent(code)),
  sshLoginApprove: (code) => request('POST', '/api/v1/ssh-login/approve', { code }),
  sshLoginDeny: (code) => request('POST', '/api/v1/ssh-login/deny', { code }),
};
