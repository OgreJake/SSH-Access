import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, fmtTime } from './common';

export default function Audit() {
  const state = useAsync(() => api.listAudit(), []);
  const [verify, setVerify] = useState(null);
  const [verifying, setVerifying] = useState(false);

  async function runVerify() {
    setVerifying(true);
    try {
      setVerify(await api.verifyAudit());
    } catch (e) {
      setVerify({ ok: false, error: e.message });
    } finally {
      setVerifying(false);
    }
  }

  return (
    <Panel
      title="Audit log"
      actions={
        <>
          <button className="btn ghost" onClick={state.reload}>
            Refresh
          </button>
          <button className="btn" onClick={runVerify} disabled={verifying}>
            {verifying ? 'Verifying…' : 'Verify chain'}
          </button>
        </>
      }
    >
      {verify && (
        <p className={verify.ok ? 'notice' : 'error'}>
          {verify.ok
            ? `Chain intact — ${verify.verified} records verified.`
            : `Chain verification FAILED: ${verify.error}`}
        </p>
      )}

      <AsyncBlock state={state} empty="No audit entries yet.">
        <table className="grid">
          <thead>
            <tr>
              <th>Seq</th>
              <th>Time</th>
              <th>Actor</th>
              <th>Event</th>
              <th>Target</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {(state.data || []).map((e) => (
              <tr key={e.seq}>
                <td>{e.seq}</td>
                <td>{fmtTime(e.at)}</td>
                <td>{e.actor}</td>
                <td>
                  <span className="tag">{e.event_type}</span>
                </td>
                <td>{e.target || '—'}</td>
                <td className="detail">{e.detail ? JSON.stringify(e.detail) : '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBlock>
    </Panel>
  );
}
