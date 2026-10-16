import React, { useState, useEffect } from 'react';

export const Assets: React.FC = () => {
  const [assets, setAssets] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/v1/assets')
      .then(res => res.json())
      .then(data => setAssets(Array.isArray(data) ? data : []))
      .catch(err => console.error(err));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-white">Asset Management</h2>
          <p className="text-xs text-slate-400">Inventory of scoped IPs, CIDR subnets, hostnames, and environments</p>
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 font-semibold uppercase">
            <tr>
              <th className="px-6 py-3">Asset Name</th>
              <th className="px-6 py-3">Target / Scope</th>
              <th className="px-6 py-3">Type</th>
              <th className="px-6 py-3">Criticality</th>
              <th className="px-6 py-3">Environment</th>
              <th className="px-6 py-3">Zone</th>
              <th className="px-6 py-3">Authorized</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2937] text-slate-300">
            {assets.length === 0 ? (
              <tr><td colSpan={7} className="px-6 py-4 text-center text-slate-500">No assets registered yet.</td></tr>
            ) : (
              assets.map(a => (
                <tr key={a.id}>
                  <td className="px-6 py-3 font-semibold text-white">{a.name}</td>
                  <td className="px-6 py-3 font-mono text-indigo-400">{a.target_value}</td>
                  <td className="px-6 py-3 uppercase text-[10px] font-bold">{a.target_type}</td>
                  <td className="px-6 py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      a.criticality === 'critical' ? 'bg-red-500/20 text-red-400' :
                      a.criticality === 'high' ? 'bg-orange-500/20 text-orange-400' : 'bg-slate-700/30 text-slate-300'
                    }`}>{a.criticality}</span>
                  </td>
                  <td className="px-6 py-3 capitalize">{a.environment}</td>
                  <td className="px-6 py-3 capitalize">{a.network_zone}</td>
                  <td className="px-6 py-3">
                    <span className="text-emerald-400 font-semibold">✓ In Scope</span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
