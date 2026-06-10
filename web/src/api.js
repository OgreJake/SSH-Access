// Thin client over the management API. The bearer token lives in sessionStorage
// for the dev workflow (option A); a real login flow replaces this alongside MFA.

const TOKEN_KEY = 'sshbroker_api_token';
let token = sessionStorage.getItem(TOKEN_KEY) || '';

export function getToken() {
  return token;
}

export function setToken(t) {
  token = t || '';
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function request(method, path, body) {
  const headers = {};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, {
    method,
    headers,
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

export const api = {
  // Used to validate the token at sign-in.
  ping: () => request('GET', '/api/v1/users'),

  listUsers: () => request('GET', '/api/v1/users'),
  createUser: (b) => request('POST', '/api/v1/users', b),
  updateUser: (id, b) => request('PATCH', `/api/v1/users/${id}`, b),
  setUserStatus: (id, status) => request('PATCH', `/api/v1/users/${id}`, { status }),
  addUserKey: (id, public_key, comment) =>
    request('POST', `/api/v1/users/${id}/keys`, { public_key, comment }),

  listServers: () => request('GET', '/api/v1/servers'),
  createServer: (b) => request('POST', '/api/v1/servers', b),
  updateServer: (id, b) => request('PATCH', `/api/v1/servers/${id}`, b),

  listGrants: () => request('GET', '/api/v1/grants'),
  createGrant: (b) => request('POST', '/api/v1/grants', b),
  updateGrant: (id, b) => request('PATCH', `/api/v1/grants/${id}`, b),
  deleteGrant: (id) => request('DELETE', `/api/v1/grants/${id}`),

  listUserGroups: () => request('GET', '/api/v1/user-groups'),
  createUserGroup: (name) => request('POST', '/api/v1/user-groups', { name }),
  addUserGroupMember: (id, user_id) =>
    request('POST', `/api/v1/user-groups/${id}/members`, { user_id }),

  listServerGroups: () => request('GET', '/api/v1/server-groups'),
  createServerGroup: (name) => request('POST', '/api/v1/server-groups', { name }),
  addServerGroupMember: (id, server_id) =>
    request('POST', `/api/v1/server-groups/${id}/members`, { server_id }),

  listSessions: () => request('GET', '/api/v1/sessions'),
  listAudit: () => request('GET', '/api/v1/audit'),
  exportAudit: () => request('GET', '/api/v1/audit/export'),
  verifyAudit: () => request('GET', '/api/v1/audit/verify'),
};
