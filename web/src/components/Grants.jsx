import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, Field, capsOf, csv } from './common';

export default function Grants() {
  const grants = useAsync(() => api.listGrants(), []);
  const refs = useAsync(
    () =>
      Promise.all([
        api.listUsers(),
        api.listUserGroups(),
        api.listServers(),
        api.listServerGroups(),
      ]).then(([users, userGroups, servers, serverGroups]) => ({
        users,
        userGroups,
        servers,
        serverGroups,
      })),
    [],
  );
  const [notice, setNotice] = useState(null);

  return (
    <Panel
      title="Grants"
      actions={<button className="btn ghost" onClick={grants.reload}>Refresh</button>}
    >
      {notice && <p className="notice">{notice}</p>}

      <AsyncBlock state={refs}>
        <CreateGrant
          refs={refs.data}
          onCreated={() => {
            setNotice('Grant created.');
            grants.reload();
          }}
        />
      </AsyncBlock>

      <AsyncBlock state={grants} empty="No grants yet.">
        <table className="grid">
          <thead>
            <tr>
              <th>Subject</th>
              <th>Target</th>
              <th>Principals</th>
              <th>Max TTL</th>
              <th>Capabilities</th>
            </tr>
          </thead>
          <tbody>
            {(grants.data || []).map((g) => (
              <tr key={g.id}>
                <td>
                  <span className="tag">{g.subject_type}</span> {g.subject}
                </td>
                <td>
                  <span className="tag">{g.target_type}</span> {g.target}
                </td>
                <td>{(g.principals || []).join(', ')}</td>
                <td>{g.max_ttl_seconds}s</td>
                <td>{capsOf(g)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBlock>
    </Panel>
  );
}

function CreateGrant({ refs, onCreated }) {
  const [subjectKind, setSubjectKind] = useState('user_group');
  const [subjectId, setSubjectId] = useState('');
  const [targetKind, setTargetKind] = useState('server_group');
  const [targetId, setTargetId] = useState('');
  const [principals, setPrincipals] = useState('');
  const [ttlMinutes, setTtlMinutes] = useState('5');
  const [caps, setCaps] = useState({ shell: false, exec: true, sftp: false, port_forward: false });
  const [recording, setRecording] = useState('metadata');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const subjectOptions = subjectKind === 'user' ? refs.users : refs.userGroups;
  const subjectLabel = (o) => (subjectKind === 'user' ? o.username : o.name);
  const targetOptions = targetKind === 'server' ? refs.servers : refs.serverGroups;
  const targetLabel = (o) => (targetKind === 'server' ? o.hostname : o.name);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.createGrant({
        subject_type: subjectKind,
        subject_id: subjectId,
        target_type: targetKind,
        target_id: targetId,
        principals: csv(principals),
        max_ttl_seconds: Math.round((parseFloat(ttlMinutes) || 5) * 60),
        shell: caps.shell,
        exec: caps.exec,
        sftp: caps.sftp,
        port_forward: caps.port_forward,
        recording,
      });
      setPrincipals('');
      setSubjectId('');
      setTargetId('');
      onCreated();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const toggle = (k) => () => setCaps((c) => ({ ...c, [k]: !c[k] }));

  return (
    <div className="subform">
      <h3>Create a grant</h3>
      <div className="form-row">
        <Field label="Subject is a">
          <select
            value={subjectKind}
            onChange={(e) => {
              setSubjectKind(e.target.value);
              setSubjectId('');
            }}
          >
            <option value="user_group">user group</option>
            <option value="user">user</option>
          </select>
        </Field>
        <Field label="Subject">
          <select value={subjectId} onChange={(e) => setSubjectId(e.target.value)}>
            <option value="">—</option>
            {(subjectOptions || []).map((o) => (
              <option key={o.id} value={o.id}>
                {subjectLabel(o)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Target is a">
          <select
            value={targetKind}
            onChange={(e) => {
              setTargetKind(e.target.value);
              setTargetId('');
            }}
          >
            <option value="server_group">server group</option>
            <option value="server">server</option>
          </select>
        </Field>
        <Field label="Target">
          <select value={targetId} onChange={(e) => setTargetId(e.target.value)}>
            <option value="">—</option>
            {(targetOptions || []).map((o) => (
              <option key={o.id} value={o.id}>
                {targetLabel(o)}
              </option>
            ))}
          </select>
        </Field>
      </div>
      <div className="form-row">
        <Field label="Principals (logins, comma-separated)">
          <input value={principals} onChange={(e) => setPrincipals(e.target.value)} placeholder="deploy, ec2-user" />
        </Field>
        <Field label="Max TTL (minutes)">
          <input value={ttlMinutes} onChange={(e) => setTtlMinutes(e.target.value)} style={{ width: 80 }} />
        </Field>
        <Field label="Recording">
          <select value={recording} onChange={(e) => setRecording(e.target.value)}>
            <option value="metadata">metadata</option>
            <option value="full">full</option>
          </select>
        </Field>
      </div>
      <div className="caps">
        {['shell', 'exec', 'sftp', 'port_forward'].map((k) => (
          <label key={k} className="check">
            <input type="checkbox" checked={caps[k]} onChange={toggle(k)} /> {k.replace('_', '-')}
          </label>
        ))}
      </div>
      <div className="form-row">
        <button
          className="btn"
          disabled={busy || !subjectId || !targetId || !principals}
          onClick={submit}
        >
          Create grant
        </button>
        {error && <span className="error">{error}</span>}
      </div>
    </div>
  );
}
