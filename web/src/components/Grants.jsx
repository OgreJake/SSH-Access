import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, Field, capsOf, csv, toCSV, downloadFile, fmtTime, useCan } from './common';

const REVIEW_LABEL = { ok: 'OK', due_soon: 'Due soon', overdue: 'Overdue', none: 'No date' };

function ReviewBadge({ status, reviewBy }) {
  const label = REVIEW_LABEL[status] || status;
  const date = reviewBy ? new Date(reviewBy).toISOString().slice(0, 10) : '—';
  return (
    <span className={'pill review-' + status} title={reviewBy ? 'Review by ' + date : 'No review date set'}>
      {label}
      {reviewBy ? ' · ' + date : ''}
    </span>
  );
}

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
  const [editing, setEditing] = useState(null); // grant being edited
  const [dueOnly, setDueOnly] = useState(false);
  const can = useCan();
  const canWrite = can('grants:write');
  const canRecertify = can('grants:recertify');

  async function remove(g) {
    if (!window.confirm(`Remove the grant ${g.subject_type}:${g.subject} → ${g.target_type}:${g.target}?`)) {
      return;
    }
    try {
      await api.deleteGrant(g.id);
      setNotice('Grant removed.');
      grants.reload();
    } catch (e) {
      setNotice('Error: ' + e.message);
    }
  }

  async function recertify(g) {
    try {
      await api.recertifyGrant(g.id);
      setNotice(`Recertified access for ${g.subject_type}:${g.subject} → ${g.target_type}:${g.target}.`);
      grants.reload();
    } catch (e) {
      setNotice('Error: ' + e.message);
    }
  }

  function exportCsv() {
    const rows = grants.data || [];
    const text = toCSV(rows, [
      { label: 'subject_type', get: (g) => g.subject_type },
      { label: 'subject', get: (g) => g.subject },
      { label: 'target_type', get: (g) => g.target_type },
      { label: 'target', get: (g) => g.target },
      { label: 'principals', get: (g) => (g.principals || []).join(' ') },
      { label: 'max_ttl_seconds', get: (g) => g.max_ttl_seconds },
      { label: 'capabilities', get: (g) => capsOf(g) },
      { label: 'recording', get: (g) => g.recording },
      { label: 'review_by', get: (g) => (g.review_by ? new Date(g.review_by).toISOString().slice(0, 10) : '') },
      { label: 'review_status', get: (g) => g.review_status },
    ]);
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    downloadFile(`access-review-${stamp}.csv`, text, 'text/csv');
  }

  const all = grants.data || [];
  const isDue = (g) => g.review_status === 'overdue' || g.review_status === 'due_soon' || g.review_status === 'none';
  const rows = dueOnly ? all.filter(isDue) : all;
  const dueCount = all.filter(isDue).length;

  return (
    <Panel
      title="Grants"
      actions={
        <>
          <button className="btn ghost" onClick={grants.reload}>
            Refresh
          </button>
          <button className="btn ghost" onClick={exportCsv} disabled={all.length === 0}>
            Export CSV
          </button>
        </>
      }
    >
      {notice && <p className="notice">{notice}</p>}

      <AsyncBlock state={refs}>
        {canWrite && (
          <CreateGrant
            refs={refs.data}
            onCreated={() => {
              setNotice('Grant created.');
              grants.reload();
            }}
          />
        )}
      </AsyncBlock>

      <AsyncBlock state={grants} empty="No grants yet.">
        <label className="check" style={{ marginBottom: 8, display: 'inline-flex' }}>
          <input type="checkbox" checked={dueOnly} onChange={(e) => setDueOnly(e.target.checked)} />{' '}
          Show only grants needing review ({dueCount})
        </label>
        <table className="grid">
          <thead>
            <tr>
              <th>Subject</th>
              <th>Target</th>
              <th>Principals</th>
              <th>Max TTL</th>
              <th>Capabilities</th>
              <th>Review</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((g) => (
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
                <td>
                  <ReviewBadge status={g.review_status} reviewBy={g.review_by} />
                </td>
                <td className="row-actions">
                  {canRecertify && g.review_status !== 'ok' && (
                    <button className="btn sm" onClick={() => recertify(g)}>
                      Recertify
                    </button>
                  )}
                  {canWrite && (
                    <button className="btn sm" onClick={() => setEditing(editing && editing.id === g.id ? null : g)}>
                      Edit
                    </button>
                  )}
                  {canWrite && (
                    <button className="btn sm danger" onClick={() => remove(g)}>
                      Remove
                    </button>
                  )}
                  {!canWrite && !canRecertify && <span className="muted">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBlock>

      {editing && (
        <EditGrant
          grant={editing}
          onSaved={() => {
            setNotice('Grant updated.');
            setEditing(null);
            grants.reload();
          }}
          onCancel={() => setEditing(null)}
        />
      )}
    </Panel>
  );
}

function EditGrant({ grant, onSaved, onCancel }) {
  const [principals, setPrincipals] = useState((grant.principals || []).join(', '));
  const [ttlMinutes, setTtlMinutes] = useState(String(Math.round((grant.max_ttl_seconds || 300) / 60)));
  const [caps, setCaps] = useState({
    shell: !!grant.shell,
    exec: !!grant.exec,
    sftp: !!grant.sftp,
  });
  const [recording, setRecording] = useState(grant.recording || 'metadata');
  const [reviewBy, setReviewBy] = useState(
    grant.review_by ? new Date(grant.review_by).toISOString().slice(0, 10) : '',
  );
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await api.updateGrant(grant.id, {
        principals: csv(principals),
        max_ttl_seconds: Math.round((parseFloat(ttlMinutes) || 5) * 60),
        shell: caps.shell,
        exec: caps.exec,
        sftp: caps.sftp,
        recording,
        review_by: reviewBy || null,
      });
      onSaved();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  const toggle = (k) => () => setCaps((c) => ({ ...c, [k]: !c[k] }));

  return (
    <div className="subform">
      <h3>
        Edit grant — <span className="tag">{grant.subject_type}</span> {grant.subject} →{' '}
        <span className="tag">{grant.target_type}</span> {grant.target}
      </h3>
      <p className="muted">Subject and target are fixed; remove and recreate to change them.</p>
      <div className="form-row">
        <Field label="Principals (logins, comma-separated)">
          <input value={principals} onChange={(e) => setPrincipals(e.target.value)} />
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
        {['shell', 'exec', 'sftp'].map((k) => (
          <label key={k} className="check">
            <input type="checkbox" checked={caps[k]} onChange={toggle(k)} /> {k.replace('_', '-')}
          </label>
        ))}
      </div>
      <div className="form-row">
        <button className="btn" disabled={busy || !principals} onClick={submit}>
          Save changes
        </button>
        <button className="btn ghost" onClick={onCancel}>
          Cancel
        </button>
        {error && <span className="error">{error}</span>}
      </div>
    </div>
  );
}

function CreateGrant({ refs, onCreated }) {
  const [subjectKind, setSubjectKind] = useState('user_group');
  const [subjectId, setSubjectId] = useState('');
  const [targetKind, setTargetKind] = useState('server_group');
  const [targetId, setTargetId] = useState('');
  const [principals, setPrincipals] = useState('');
  const [ttlMinutes, setTtlMinutes] = useState('5');
  const [caps, setCaps] = useState({ shell: false, exec: true, sftp: false });
  const [recording, setRecording] = useState('metadata');
  const [reviewBy, setReviewBy] = useState('');
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
        recording,
        review_by: reviewBy || null,
      });
      setPrincipals('');
      setSubjectId('');
      setTargetId('');
      setReviewBy('');
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
        <Field label="Review by (optional)">
          <input
            type="date"
            value={reviewBy}
            onChange={(e) => setReviewBy(e.target.value)}
            title="Defaults to the configured review interval if left blank"
          />
        </Field>
      </div>
      <div className="caps">
        {['shell', 'exec', 'sftp'].map((k) => (
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
