import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, Field, useForm, csv } from './common';

export default function Servers() {
  const state = useAsync(() => api.listServers(), []);
  const [notice, setNotice] = useState(null);
  const [editing, setEditing] = useState(null);

  async function remove(s) {
    if (
      !window.confirm(
        `Remove server "${s.hostname}"?\n\nThis deletes its server-group memberships and any grants targeting it directly. Recorded sessions are kept (their server reference is cleared but the label remains).`,
      )
    ) {
      return;
    }
    try {
      await api.deleteServer(s.id);
      setNotice(`Removed server "${s.hostname}".`);
      state.reload();
    } catch (e) {
      setNotice('Error: ' + e.message);
    }
  }

  return (
    <Panel
      title="Servers"
      actions={<button className="btn ghost" onClick={state.reload}>Refresh</button>}
    >
      {notice && <p className="notice">{notice}</p>}

      <CreateServer
        onCreated={() => {
          setNotice('Server created.');
          state.reload();
        }}
      />

      <AsyncBlock state={state} empty="No servers yet.">
        <table className="grid">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Address</th>
              <th>Port</th>
              <th>Mode</th>
              <th>Allowed principals</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(state.data || []).map((s) => (
              <tr key={s.id}>
                <td>{s.hostname}</td>
                <td>{s.address}</td>
                <td>{s.port}</td>
                <td>{s.access_mode}</td>
                <td>{(s.allowed_principals || []).join(', ') || '—'}</td>
                <td className="row-actions">
                  <button className="btn sm" onClick={() => setEditing(editing && editing.id === s.id ? null : s)}>
                    Edit
                  </button>
                  <button className="btn sm danger" onClick={() => remove(s)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBlock>

      {editing && (
        <EditServer
          server={editing}
          onSaved={() => {
            setNotice('Server updated.');
            setEditing(null);
            state.reload();
          }}
          onCancel={() => setEditing(null)}
        />
      )}
    </Panel>
  );
}

function EditServer({ server, onSaved, onCancel }) {
  const { values, set } = useForm({
    hostname: server.hostname,
    address: server.address,
    port: String(server.port),
    host_key_fingerprint: server.host_key_fingerprint || '',
    access_mode: server.access_mode,
    principals: (server.allowed_principals || []).join(', '),
  });
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.updateServer(server.id, {
        hostname: values.hostname,
        address: values.address,
        port: parseInt(values.port, 10) || 22,
        host_key_fingerprint: values.host_key_fingerprint,
        access_mode: values.access_mode,
        allowed_principals: csv(values.principals),
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
      <h3>Edit server — {server.hostname}</h3>
      <div className="form-row">
        <Field label="Hostname (alias)">
          <input value={values.hostname} onChange={set('hostname')} />
        </Field>
        <Field label="Address">
          <input value={values.address} onChange={set('address')} />
        </Field>
        <Field label="Port">
          <input value={values.port} onChange={set('port')} style={{ width: 70 }} />
        </Field>
        <Field label="Access mode">
          <select value={values.access_mode} onChange={set('access_mode')}>
            <option value="cert">cert</option>
            <option value="jit_key">jit_key</option>
            <option value="stored_cred">stored_cred</option>
          </select>
        </Field>
      </div>
      <div className="form-row">
        <Field label="Host key fingerprint (SHA256:…)">
          <input
            value={values.host_key_fingerprint}
            onChange={set('host_key_fingerprint')}
            style={{ minWidth: 320 }}
          />
        </Field>
        <Field label="Allowed principals (comma-separated)">
          <input value={values.principals} onChange={set('principals')} />
        </Field>
        <button className="btn" disabled={busy || !values.hostname || !values.address} onClick={submit}>
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

function CreateServer({ onCreated }) {
  const { values, set, reset } = useForm({
    hostname: '',
    address: '',
    port: '22',
    host_key_fingerprint: '',
    access_mode: 'cert',
    principals: '',
  });
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.createServer({
        hostname: values.hostname,
        address: values.address,
        port: parseInt(values.port, 10) || 22,
        host_key_fingerprint: values.host_key_fingerprint,
        access_mode: values.access_mode,
        allowed_principals: csv(values.principals),
      });
      reset();
      onCreated();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="subform">
      <h3>Register a server</h3>
      <div className="form-row">
        <Field label="Hostname (alias)">
          <input value={values.hostname} onChange={set('hostname')} placeholder="web01" />
        </Field>
        <Field label="Address">
          <input value={values.address} onChange={set('address')} placeholder="10.0.0.5" />
        </Field>
        <Field label="Port">
          <input value={values.port} onChange={set('port')} style={{ width: 70 }} />
        </Field>
        <Field label="Access mode">
          <select value={values.access_mode} onChange={set('access_mode')}>
            <option value="cert">cert</option>
            <option value="jit_key">jit_key</option>
            <option value="stored_cred">stored_cred</option>
          </select>
        </Field>
      </div>
      <div className="form-row">
        <Field label="Host key fingerprint (SHA256:…, optional)">
          <input
            value={values.host_key_fingerprint}
            onChange={set('host_key_fingerprint')}
            placeholder="SHA256:…"
            style={{ minWidth: 320 }}
          />
        </Field>
        <Field label="Allowed principals (comma-separated, enforced)">
          <input value={values.principals} onChange={set('principals')} placeholder="deploy, ec2-user" />
        </Field>
        <button className="btn" disabled={busy || !values.hostname || !values.address} onClick={submit}>
          Add server
        </button>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
