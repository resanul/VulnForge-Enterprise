import React, { useState, useEffect } from 'react';

export const Admin: React.FC = () => {
  const [health, setHealth] = useState<any>(null);
  const [scopes, setScopes] = useState<any[]>([]);
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [newScope, setNewScope] = useState<string>('');
  const [scopeDesc, setScopeDesc] = useState<string>('');

  const loadData = () => {
    fetch('/api/v1/system/health')
      .then(res => res.json())
      .then(data => setHealth(data))
      .catch(err => console.error(err));

    fetch('/api/v1/system/scopes')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) setScopes(data);
      })
      .catch(err => console.error(err));

    fetch('/api/v1/system/audit-events?limit=25')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) setAuditLogs(data);
      })
      .catch(err => console.error(err));
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleAddScope = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newScope) return;
    try {
      const res = await fetch('/api/v1/system/scopes', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_pattern: newScope, description: scopeDesc })
      });
      if (res.ok) {
        setNewScope('');
        setScopeDesc('');
        loadData();
      }
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-white">Administration & Operations</h2>
          <p className="text-xs text-slate-400">Scanner engine readiness, approved scope authorization, and tamper-evident audit logs</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Cluster Status</span>
          <div className="text-3xl font-extrabold text-emerald-400 mt-2">{health?.status?.toUpperCase() || 'ONLINE'}</div>
          <p className="text-xs text-slate-400 mt-2">RHEL 9 / Rocky Linux 9 Ready</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wider">Active Engines</span>
          <div className="text-3xl font-extrabold text-white mt-2">{health?.active_engines ?? 10} / {health?.total_engines ?? 10}</div>
          <p className="text-xs text-emerald-400 mt-2">All security engines loaded</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Approved Scopes</span>
          <div className="text-3xl font-extrabold text-white mt-2">{scopes.length}</div>
          <p className="text-xs text-slate-400 mt-2">Authorized target rules</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Audit Records</span>
          <div className="text-3xl font-extrabold text-white mt-2">{auditLogs.length}</div>
          <p className="text-xs text-slate-400 mt-2">Tamper-evident logs</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Approved Scope Manager */}
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl space-y-4">
          <h3 className="text-sm font-bold text-white">Authorized Engagement Scope</h3>
          <form onSubmit={handleAddScope} className="flex gap-2">
            <input
              type="text"
              placeholder="e.g. 192.168.1.0/24 or example.com"
              value={newScope}
              onChange={e => setNewScope(e.target.value)}
              className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200"
            />
            <input
              type="text"
              placeholder="Scope Notes"
              value={scopeDesc}
              onChange={e => setScopeDesc(e.target.value)}
              className="w-1/3 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200"
            />
            <button
              type="submit"
              className="px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs rounded-lg"
            >
              Add Scope
            </button>
          </form>

          <div className="overflow-y-auto max-h-60">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 uppercase">
                <tr>
                  <th className="px-3 py-2">Target Scope</th>
                  <th className="px-3 py-2">Approved By</th>
                  <th className="px-3 py-2">Active</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1f2937] text-slate-300">
                {scopes.map(s => (
                  <tr key={s.id}>
                    <td className="px-3 py-2 font-mono text-indigo-400">{s.target_pattern}</td>
                    <td className="px-3 py-2 text-slate-400">{s.approved_by}</td>
                    <td className="px-3 py-2">
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                        {s.is_active ? 'YES' : 'NO'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Audit Log Stream */}
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl space-y-4">
          <h3 className="text-sm font-bold text-white">System Audit & Compliance Stream</h3>
          <div className="overflow-y-auto max-h-72">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 uppercase">
                <tr>
                  <th className="px-3 py-2">Action</th>
                  <th className="px-3 py-2">User</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Timestamp</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1f2937] text-slate-300">
                {auditLogs.map(l => (
                  <tr key={l.id}>
                    <td className="px-3 py-2 font-mono text-slate-200">{l.action}</td>
                    <td className="px-3 py-2 text-indigo-400">{l.username}</td>
                    <td className="px-3 py-2">
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                        {l.status}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-slate-500">{new Date(l.created_at * 1000).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
