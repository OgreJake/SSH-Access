import { useState, useEffect } from 'react';
import { api } from '../api';

// SshLogin is the standalone approval page reached at /ssh-login?code=… from the
// URL the broker prints in the user's terminal (ADR-021). It is served behind
// oauth2-proxy via the /api calls; if the user has no SSO session yet, the info
// call returns 401 and we send them through SSO, returning here afterward.
export default function SshLogin() {
  const code = new URLSearchParams(window.location.search).get('code') || '';
  const [state, setState] = useState({ phase: 'loading' });
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!code) {
      setState({ phase: 'error', msg: 'This link is missing its approval code.' });
      return;
    }
    (async () => {
      try {
        const info = await api.sshLoginInfo(code);
        setState({ phase: 'review', info });
      } catch (e) {
        if (e.status === 401) {
          // Not signed in yet. oauth2-proxy lives on its own domain, returned as
          // auth_url in the 401 body, so bounce there (not a broker-relative
          // path). rd is the absolute approval URL so we land back here with the
          // code after SSO; the broker origin must be in oauth2-proxy's
          // whitelist_domains for this cross-origin redirect to be allowed.
          const base = e.body?.auth_url || '';
          const rd = encodeURIComponent(window.location.origin + '/ssh-login?code=' + code);
          if (base) {
            window.location.href = base + '/oauth2/start?rd=' + rd;
          } else {
            setState({ phase: 'error', msg: 'SSO is not configured (no auth_url from server).' });
          }
          return;
        }
        if (e.status === 404) {
          setState({ phase: 'expired' });
          return;
        }
        setState({ phase: 'error', msg: e.message || 'Could not load this request.' });
      }
    })();
  }, [code]);

  async function decide(approve) {
    setBusy(true);
    try {
      if (approve) await api.sshLoginApprove(code);
      else await api.sshLoginDeny(code);
      setState({ phase: approve ? 'approved' : 'denied' });
    } catch (e) {
      setState({ phase: e.status === 404 ? 'expired' : 'error', msg: e.message || 'Action failed.' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gate">
      <div className="gate-card">
        <div className="brand">
          sshbroker <span>ssh sign-in</span>
        </div>

        {state.phase === 'loading' && <p className="muted">Loading request…</p>}

        {state.phase === 'review' && (
          <>
            <p>Approve this SSH connection?</p>
            <dl className="kv">
              <dt>Target</dt>
              <dd>{state.info.requested_target || '—'}</dd>
              <dt>From</dt>
              <dd>{state.info.source_ip || '—'}</dd>
              <dt>As</dt>
              <dd>{state.info.approver}</dd>
            </dl>
            <p className="muted small">
              Only approve if you started this connection from the address above. If you didn't, deny it.
            </p>
            <div className="form-row">
              <button className="btn" disabled={busy} onClick={() => decide(true)}>
                {busy ? 'Working…' : 'Approve'}
              </button>
              <button className="btn danger" disabled={busy} onClick={() => decide(false)}>
                Deny
              </button>
            </div>
          </>
        )}

        {state.phase === 'approved' && (
          <p className="notice">Approved. Return to your terminal — your SSH session will continue.</p>
        )}
        {state.phase === 'denied' && <p className="notice">Denied. The SSH connection was refused.</p>}
        {state.phase === 'expired' && (
          <p className="error">This request has expired or was already used. Start a new SSH connection to try again.</p>
        )}
        {state.phase === 'error' && <p className="error">{state.msg}</p>}
      </div>
    </div>
  );
}
