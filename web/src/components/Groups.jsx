import { useState } from 'react';
import { api } from '../api';
import { useAsync, Panel, AsyncBlock, Field, useCan } from './common';

export default function Groups() {
  const userGroups = useAsync(() => api.listUserGroups(), []);
  const serverGroups = useAsync(() => api.listServerGroups(), []);
  const users = useAsync(() => api.listUsers(), []);
  const servers = useAsync(() => api.listServers(), []);
  const [notice, setNotice] = useState(null);
  const can = useCan();
  const canWrite = can('groups:write');

  return (
    <Panel
      title="Groups"
      actions={
        <button
          className="btn ghost"
          onClick={() => {
            userGroups.reload();
            serverGroups.reload();
          }}
        >
          Refresh
        </button>
      }
    >
      {notice && <p className="notice">{notice}</p>}

      <div className="two-col">
        <GroupColumn
          kind="User"
          canWrite={canWrite}
          groupsState={userGroups}
          membersState={users}
          memberLabel={(u) => u.username}
          createGroup={(name) => api.createUserGroup(name)}
          addMember={(gid, id) => api.addUserGroupMember(gid, id)}
          onChange={(m) => {
            setNotice(m);
            userGroups.reload();
          }}
        />
        <GroupColumn
          kind="Server"
          canWrite={canWrite}
          groupsState={serverGroups}
          membersState={servers}
          memberLabel={(s) => s.hostname}
          createGroup={(name) => api.createServerGroup(name)}
          addMember={(gid, id) => api.addServerGroupMember(gid, id)}
          onChange={(m) => {
            setNotice(m);
            serverGroups.reload();
          }}
        />
      </div>
    </Panel>
  );
}

function GroupColumn({ kind, groupsState, membersState, memberLabel, createGroup, addMember, onChange, canWrite }) {
  const [name, setName] = useState('');
  const [selGroup, setSelGroup] = useState('');
  const [selMember, setSelMember] = useState('');
  const [error, setError] = useState(null);

  async function create() {
    setError(null);
    try {
      await createGroup(name);
      setName('');
      onChange(`${kind} group created.`);
    } catch (e) {
      setError(e.message);
    }
  }

  async function join() {
    setError(null);
    try {
      await addMember(selGroup, selMember);
      onChange('Member added.');
    } catch (e) {
      setError(e.message);
    }
  }

  const members = membersState.data || [];
  const idField = kind === 'User' ? 'id' : 'id';

  return (
    <div className="col">
      <h3>{kind} groups</h3>

      {canWrite && (
        <div className="form-row">
          <Field label="New group name">
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder={kind === 'User' ? 'deployers' : 'web-tier'} />
          </Field>
          <button className="btn" disabled={!name} onClick={create}>
            Create
          </button>
        </div>
      )}

      <AsyncBlock state={groupsState} empty="No groups yet.">
        <table className="grid">
          <thead>
            <tr>
              <th>Name</th>
              <th>Members</th>
            </tr>
          </thead>
          <tbody>
            {(groupsState.data || []).map((g) => (
              <tr key={g.id}>
                <td>{g.name}</td>
                <td>{g.members}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </AsyncBlock>

      {canWrite && (
        <div className="subform">
          <h4>Add a member</h4>
          <div className="form-row">
            <Field label="Group">
              <select value={selGroup} onChange={(e) => setSelGroup(e.target.value)}>
                <option value="">—</option>
                {(groupsState.data || []).map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </Field>
            <Field label={kind === 'User' ? 'User' : 'Server'}>
              <select value={selMember} onChange={(e) => setSelMember(e.target.value)}>
                <option value="">—</option>
                {members.map((m) => (
                  <option key={m[idField]} value={m[idField]}>
                    {memberLabel(m)}
                  </option>
                ))}
              </select>
            </Field>
            <button className="btn" disabled={!selGroup || !selMember} onClick={join}>
              Add
            </button>
          </div>
          {error && <p className="error">{error}</p>}
        </div>
      )}
    </div>
  );
}
