import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, Field, useForm, csv } from './common';

export default function Servers() {
  const state = useAsync(() => api.listServers(), []);
  const [notice, setNotice] = useState(null);

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
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBlock>
    </Panel>
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
