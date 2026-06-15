import { useState, useEffect } from 'react';
import { api } from './api';
import { PermsProvider } from './components/common';
import Users from './components/Users';
import Servers from './components/Servers';
import Groups from './components/Groups';
import Grants from './components/Grants';
import Sessions from './components/Sessions';
import Audit from './components/Audit';

// Tabs gated on the read permission for that resource (ADR-020). Built-in admin
// and auditor both read everything; this matters for future custom roles.
const TABS = [
  ['users', 'Users', 'users:read'],
  ['servers', 'Servers', 'servers:read'],
  ['groups', 'Groups', 'groups:read'],
  ['grants', 'Grants', 'grants:read'],
  ['sessions', 'Sessions', 'sessions:read'],
  ['audit', 'Audit', 'audit:read'],
];

export default function App() {
  const [state, setState] = useState({ status: 'loading', identity: null });
  const [tab, setTab] = useState('users');

  async function loadIdentity() {
    try {
      const id = await api.whoami();
      setState({ status: 'authed', identity: id });
    } catch (e) {
      setState({ status: e.status === 401 ? 'anon' : 'error', identity: null, error: e.message });
    }
  }

  useEffect(() => {
    loadIdentity();
  }, []);

  if (state.status === 'loading') {
    return <div className="gate"><div className="gate-card"><p className="muted">Loading…</p></div></div>;
  }
  if (state.status !== 'authed') {
    return <SignIn onSignedIn={loadIdentity} error={state.status === 'error' ? state.error : null} />;
  }

  const id = state.identity;
  const perms = new Set(id.permissions || []);
  const visibleTabs = TABS.filter(([, , p]) => perms.has(p));
  if (visibleTabs.length && !visibleTabs.some(([k]) => k === tab)) {
    // current tab not permitted; snap to the first visible one
    setTab(visibleTabs[0][0]);
  }

  async function signOut() {
    try {
      await api.localLogout();
    } catch {
      /* ignore */
    }
    // For SSO sessions the proxy holds the Entra session; reloading re-checks
    // auth and (behind the proxy) would redirect to sign-in.
    window.location.reload();
  }

  return (
    <PermsProvider value={id}>
      <div className="app">
        <header className="topbar">
          <div className="brand">
            sshbroker <span>admin</span>
          </div>
          <nav className="tabs">
            {visibleTabs.map(([k, label]) => (
              <button key={k} className={tab === k ? 'tab active' : 'tab'} onClick={() => setTab(k)}>
                {label}
              </button>
            ))}
          </nav>
          <div className="identity">
            <span className="who" title={(id.roles || []).join(', ')}>
              {id.subject} <span className="src">{id.source}</span>
            </span>
            <button className="btn ghost" onClick={signOut}>
              Sign out
            </button>
          </div>
        </header>
        <main className="content">
          {tab === 'users' && <Users />}
          {tab === 'servers' && <Servers />}
          {tab === 'groups' && <Groups />}
          {tab === 'grants' && <Grants />}
          {tab === 'sessions' && <Sessions />}
          {tab === 'audit' && <Audit />}
        </main>
      </div>
    </PermsProvider>
  );
}

function SignIn({ onSignedIn, error }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(error || null);

  async function submit() {
    if (!username || !password) return;
    setBusy(true);
    setErr(null);
    try {
      await api.localLogin(username, password);
      onSignedIn();
    } catch (e) {
      setErr(e.status === 401 ? 'Invalid credentials.' : e.message || 'Sign-in failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gate">
      <div className="gate-card">
        <div className="brand">
          sshbroker <span>admin</span>
        </div>
        <p className="muted">Sign in with your organization account (SSO), or use a break-glass admin.</p>
        <a className="btn" href="/oauth2/start?rd=/">
          Sign in with SSO
        </a>
        <div className="divider">break-glass</div>
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="username"
          autoComplete="username"
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && submit()}
          placeholder="password"
          autoComplete="current-password"
        />
        <button className="btn ghost" disabled={busy || !username || !password} onClick={submit}>
          {busy ? 'Signing in…' : 'Break-glass sign in'}
        </button>
        {err && <p className="error">{err}</p>}
      </div>
    </div>
  );
}
