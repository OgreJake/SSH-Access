import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, Field, useForm } from './common';

export default function Users() {
  const state = useAsync(() => api.listUsers(), []);
  const [notice, setNotice] = useState(null);
  const [keyFor, setKeyFor] = useState(null); // user id we're adding a key to
  const [editing, setEditing] = useState(null); // user being edited

  async function remove(u) {
    if (
      !window.confirm(
        `Remove user "${u.username}"?\n\nThis deletes their public keys, group memberships, and any grants made directly to them. Recorded sessions are kept for the audit trail.`,
      )
    ) {
      return;
    }
    try {
      await api.deleteUser(u.id);
      setNotice(`Removed user "${u.username}".`);
      state.reload();
    } catch (e) {
      setNotice('Error: ' + e.message);
    }
  }

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
                  <button className="btn sm" onClick={() => setEditing(editing && editing.id === u.id ? null : u)}>
                    Edit
                  </button>
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
                  <button className="btn sm danger" onClick={() => remove(u)}>
                    Remove
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

      {editing && (
        <EditUser
          user={editing}
          onSaved={() => {
            setNotice('User updated.');
            setEditing(null);
            state.reload();
          }}
          onCancel={() => setEditing(null)}
        />
      )}
    </Panel>
  );
}

function EditUser({ user, onSaved, onCancel }) {
  const { values, set } = useForm({
    username: user.username,
    email: user.email || '',
    source: user.source,
    status: user.status,
  });
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.updateUser(user.id, {
        username: values.username,
        email: values.email,
        source: values.source,
        status: values.status,
      });
      onSaved();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="subform">
      <h3>Edit user — {user.username}</h3>
      <div className="form-row">
        <Field label="Username">
          <input value={values.username} onChange={set('username')} />
        </Field>
        <Field label="Email">
          <input value={values.email} onChange={set('email')} />
        </Field>
        <Field label="Source">
          <select value={values.source} onChange={set('source')}>
            <option value="local">local</option>
            <option value="entra">entra</option>
          </select>
        </Field>
        <Field label="Status">
          <select value={values.status} onChange={set('status')}>
            <option value="active">active</option>
            <option value="disabled">disabled</option>
          </select>
        </Field>
        <button className="btn" disabled={busy || !values.username} onClick={submit}>
          Save changes
        </button>
        <button className="btn ghost" onClick={onCancel}>
          Cancel
        </button>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
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
