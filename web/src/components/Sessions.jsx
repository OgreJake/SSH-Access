import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, fmtTime, downloadFile } from './common';

export default function Sessions() {
  const state = useAsync(() => api.listSessions(), []);
  const [notice, setNotice] = useState(null);

  async function terminate(s) {
    if (!window.confirm(`Terminate ${s.subject}'s active session on ${s.server}? The broker will kill it within a few seconds.`)) {
      return;
    }
    try {
      await api.terminateSession(s.id);
      setNotice(`Termination requested for ${s.subject}'s session on ${s.server}.`);
      state.reload();
    } catch (e) {
      setNotice('Error: ' + e.message);
    }
  }

  async function getRecording(s) {
    try {
      const cast = await api.downloadRecording(s.id);
      downloadFile(`session-${s.id}.cast`, cast, 'application/x-asciicast');
      setNotice('Recording downloaded. Play it with: asciinema play session-' + s.id + '.cast');
    } catch (e) {
      setNotice('Error: ' + e.message);
    }
  }

  return (
    <Panel
      title="Recent sessions"
      actions={<button className="btn ghost" onClick={state.reload}>Refresh</button>}
    >
      {notice && <p className="notice">{notice}</p>}
      <AsyncBlock state={state} empty="No sessions recorded yet.">
        <table className="grid">
          <thead>
            <tr>
              <th>Started</th>
              <th>Subject</th>
              <th>Server</th>
              <th>Login</th>
              <th>Source IP</th>
              <th>In/Out</th>
              <th>Exit</th>
              <th>Rec</th>
              <th>Ended</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {(state.data || []).map((s) => (
              <tr key={s.id}>
                <td>{fmtTime(s.started_at)}</td>
                <td>{s.subject}</td>
                <td>{s.server}</td>
                <td>{s.login}</td>
                <td>{s.source_ip || '—'}</td>
                <td>
                  {s.bytes_in}/{s.bytes_out}
                </td>
                <td>{s.exit_status === null || s.exit_status === undefined ? '—' : s.exit_status}</td>
                <td>{s.recording === 'full' ? <span className="tag">full</span> : '—'}</td>
                <td>{s.ended_at ? fmtTime(s.ended_at) : <span className="pill ok">active</span>}</td>
                <td className="row-actions">
                  {!s.ended_at && (
                    <button className="btn sm danger" onClick={() => terminate(s)}>
                      Terminate
                    </button>
                  )}
                  {s.recording_url ? (
                    <button
                      className="btn sm"
                      onClick={() => window.open(s.recording_url, '_blank', 'noopener,noreferrer')}
                    >
                      View recording
                    </button>
                  ) : (
                    s.has_recording && (
                      <button className="btn sm" onClick={() => getRecording(s)}>
                        Download
                      </button>
                    )
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBlock>
    </Panel>
  );
}
