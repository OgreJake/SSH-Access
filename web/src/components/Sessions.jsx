import { api } from '../api';
import { useAsync, Panel, AsyncBlock, fmtTime } from './common';

export default function Sessions() {
  const state = useAsync(() => api.listSessions(), []);

  return (
    <Panel
      title="Recent sessions"
      actions={<button className="btn ghost" onClick={state.reload}>Refresh</button>}
    >
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
              <th>Ended</th>
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
                <td>{s.ended_at ? fmtTime(s.ended_at) : <span className="pill ok">active</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBlock>
    </Panel>
  );
}
