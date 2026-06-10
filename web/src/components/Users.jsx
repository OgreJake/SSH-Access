import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, Field, useForm } from './common';

export default function Users() {
  const state = useAsync(() => api.listUsers(), []);
  const [notice, setNotice] = useState(null);
  const [keyFor, setKeyFor] = useState(null); // user id we're adding a key to

  return (
    <Panel
      title="Users"
      actions={<button className="btn ghost" onClick={state.reload}>Refresh</button>}
    >
      {notice && <p className="notice">{notice}</p>}

      <CreateUser
        onCreated={(u) => {
          setNotice(`Created user (id ${u.id}).`);
          state.reload();
        }}
      />

      <AsyncBlock state={state} empty="No users yet.">
        <table className="grid">
          <thead>
            <tr>
              <th>Username</th>
              <th>Email</th>
              <th>Source</th>
              <th>Status</th>
              <th>Keys</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(state.data || []).map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td>{u.email || '—'}</td>
                <td>{u.source}</td>
                <td>
                  <span className={u.status === 'active' ? 'pill ok' : 'pill off'}>{u.status}</span>
                </td>
                <td>{u.key_count}</td>
                <td className="row-actions">
                  <button className="btn sm" onClick={() => setKeyFor(keyFor === u.id ? null : u.id)}>
                    Add key
                  </button>
                  <button
                    className="btn sm"
                    onClick={async () => {
                      const next = u.status === 'active' ? 'disabled' : 'active';
                      await api.setUserStatus(u.id, next);
                      setNotice(`${u.username} is now ${next}.`);
                      state.reload();
                    }}
                  >
                    {u.status === 'active' ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBlock>

      {keyFor && (
        <AddKey
          userId={keyFor}
          onAdded={() => {
            setNotice('Key added.');
            setKeyFor(null);
            state.reload();
          }}
          onCancel={() => setKeyFor(null)}
        />
      )}
    </Panel>
  );
}

function CreateUser({ onCreated }) {
  const { values, set, reset } = useForm({ username: '', email: '', source: 'local' });
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.createUser({
        username: values.username,
        email: values.email,
        source: values.source,
      });
      reset();
      onCreated(res);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="form-row">
      <Field label="Username">
        <input value={values.username} onChange={set('username')} placeholder="alice" />
      </Field>
      <Field label="Email">
        <input value={values.email} onChange={set('email')} placeholder="alice@example.com" />
      </Field>
      <Field label="Source">
        <select value={values.source} onChange={set('source')}>
          <option value="local">local</option>
          <option value="entra">entra</option>
        </select>
      </Field>
      <button className="btn" disabled={busy || !values.username} onClick={submit}>
        Add user
      </button>
      {error && <span className="error">{error}</span>}
    </div>
  );
}

function AddKey({ userId, onAdded, onCancel }) {
  const [key, setKey] = useState('');
  const [comment, setComment] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.addUserKey(userId, key, comment);
      setKey('');
      setComment('');
      onAdded();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="subform">
      <h3>Add a public key</h3>
      <Field label="Public key (authorized_keys line)">
        <textarea
          rows={2}
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="ssh-ed25519 AAAA..."
        />
      </Field>
      <div className="form-row">
        <Field label="Comment">
          <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="laptop" />
        </Field>
        <button className="btn" disabled={busy || !key} onClick={submit}>
          Save key
        </button>
        <button className="btn ghost" onClick={onCancel}>
          Cancel
        </button>
        {error && <span className="error">{error}</span>}
      </div>
    </div>
  );
}
