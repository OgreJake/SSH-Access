import { useState } from 'react';
import { api, getToken, setToken } from './api';
import Users from './components/Users';
import Servers from './components/Servers';
import Groups from './components/Groups';
import Grants from './components/Grants';
import Sessions from './components/Sessions';
import Audit from './components/Audit';

const TABS = [
  ['users', 'Users'],
  ['servers', 'Servers'],
  ['groups', 'Groups'],
  ['grants', 'Grants'],
  ['sessions', 'Sessions'],
  ['audit', 'Audit'],
];

export default function App() {
  const [token, setTok] = useState(getToken());
  const [tab, setTab] = useState('users');

  if (!token) {
    return (
      <TokenGate
        onConnect={(t) => {
          setToken(t);
          setTok(t);
        }}
      />
    );
  }

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          sshbroker <span>admin</span>
        </div>
        <nav className="tabs">
          {TABS.map(([k, label]) => (
            <button key={k} className={tab === k ? 'tab active' : 'tab'} onClick={() => setTab(k)}>
              {label}
            </button>
          ))}
        </nav>
        <button
          className="btn ghost"
          onClick={() => {
            setToken('');
            setTok('');
          }}
        >
          Sign out
        </button>
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
  );
}

function TokenGate({ onConnect }) {
  const [value, setValue] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function connect() {
    setBusy(true);
    setError(null);
    setToken(value);
    try {
      await api.ping();
      onConnect(value);
    } catch (e) {
      setToken('');
      setError(e.status === 401 ? 'Invalid token.' : e.message || 'Connection failed.');
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
        <p className="muted">Enter the management API token to continue.</p>
        <input
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && value && connect()}
          placeholder="API token"
          autoFocus
        />
        <button className="btn" disabled={busy || !value} onClick={connect}>
          {busy ? 'Connecting…' : 'Connect'}
        </button>
        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}
