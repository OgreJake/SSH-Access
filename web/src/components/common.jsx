import { useState, useEffect, useCallback } from 'react';

// useAsync runs an async function on mount (and on demand via reload),
// tracking loading/error/data.
export function useAsync(fn, deps = []) {
  const [state, setState] = useState({ loading: true, error: null, data: null });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(() => {
    setState((s) => ({ ...s, loading: true, error: null }));
    fn()
      .then((data) => setState({ loading: false, error: null, data }))
      .catch((e) => setState({ loading: false, error: e.message || String(e), data: null }));
  }, deps);
  useEffect(() => {
    run();
  }, [run]);
  return { ...state, reload: run };
}

export function Panel({ title, actions, children }) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>{title}</h2>
        <div className="panel-actions">{actions}</div>
      </div>
      {children}
    </section>
  );
}

export function AsyncBlock({ state, empty, children }) {
  if (state.loading) return <p className="muted">Loading…</p>;
  if (state.error) return <p className="error">Error: {state.error}</p>;
  if (empty && (!state.data || state.data.length === 0)) return <p className="muted">{empty}</p>;
  return children;
}

export function Field({ label, children }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

// useForm gives a tiny controlled-form helper.
export function useForm(initial) {
  const [values, setValues] = useState(initial);
  const set = (k) => (e) => {
    const v = e && e.target ? (e.target.type === 'checkbox' ? e.target.checked : e.target.value) : e;
    setValues((s) => ({ ...s, [k]: v }));
  };
  const reset = () => setValues(initial);
  return { values, set, reset, setValues };
}

export function fmtTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export function capsOf(g) {
  const c = [];
  if (g.shell) c.push('shell');
  if (g.exec) c.push('exec');
  if (g.sftp) c.push('sftp');
  if (g.port_forward) c.push('port-forward');
  return c.length ? c.join(', ') : '—';
}

export function csv(s) {
  return (s || '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

// downloadFile triggers a browser download of in-memory text.
export function downloadFile(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// toCSV renders rows to CSV. columns: [{ label, get(row) }].
export function toCSV(rows, columns) {
  const esc = (v) => {
    const s = v === null || v === undefined ? '' : String(v);
    return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const head = columns.map((c) => esc(c.label)).join(',');
  const body = rows.map((r) => columns.map((c) => esc(c.get(r))).join(',')).join('\n');
  return head + '\n' + body + '\n';
}
