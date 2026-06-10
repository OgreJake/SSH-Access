import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, fmtTime, downloadFile, toCSV } from './common';

export default function Audit() {
  const state = useAsync(() => api.listAudit(), []);
  const [verify, setVerify] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState(null);

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

  async function download(format) {
    setExporting(true);
    setExportError(null);
    try {
      const entries = await api.exportAudit(); // full log, oldest-first
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      if (format === 'json') {
        downloadFile(`audit-${stamp}.json`, JSON.stringify(entries, null, 2), 'application/json');
      } else {
        const csvText = toCSV(entries || [], [
          { label: 'seq', get: (e) => e.seq },
          { label: 'at', get: (e) => e.at },
          { label: 'actor', get: (e) => e.actor },
          { label: 'event_type', get: (e) => e.event_type },
          { label: 'target', get: (e) => e.target },
          { label: 'detail', get: (e) => (e.detail ? JSON.stringify(e.detail) : '') },
        ]);
        downloadFile(`audit-${stamp}.csv`, csvText, 'text/csv');
      }
    } catch (e) {
      setExportError(e.message);
    } finally {
      setExporting(false);
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
          <button className="btn ghost" disabled={exporting} onClick={() => download('csv')}>
            Download CSV
          </button>
          <button className="btn ghost" disabled={exporting} onClick={() => download('json')}>
            Download JSON
          </button>
          <button className="btn" onClick={runVerify} disabled={verifying}>
            {verifying ? 'Verifying…' : 'Verify chain'}
          </button>
        </>
      }
    >
      {exportError && <p className="error">Export failed: {exportError}</p>}
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
