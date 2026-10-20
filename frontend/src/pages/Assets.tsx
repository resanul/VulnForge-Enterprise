import React, { useState, useEffect } from 'react';
import { Server, Plus, ShieldCheck, Search } from 'lucide-react';

export const Assets: React.FC = () => {
  const [assets, setAssets] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetch('/api/v1/assets')
      .then(res => res.json())
      .then(data => setAssets(Array.isArray(data) ? data : []))
      .catch(err => console.error(err));
  }, []);

  const criticalityClass: Record<string, string> = {
    critical: 'bg-red-500/15 text-red-500 dark:text-red-400 border border-red-500/30',
    high: 'bg-orange-500/15 text-orange-500 dark:text-orange-400 border border-orange-500/30',
    medium: 'bg-amber-500/15 text-amber-500 dark:text-amber-400 border border-amber-500/30',
    low: 'bg-blue-500/15 text-blue-500 dark:text-blue-400 border border-blue-500/30',
  };

  const filteredAssets = assets.filter(a =>
    (a.name || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (a.target_value || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
    (a.environment || '').toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">Asset Inventory</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Scoped IP addresses, CIDR network ranges, hostnames, and enterprise environment classification
          </p>
        </div>

        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-60">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Filter assets..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>
          <button 
            className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white rounded-xl shadow-xs transition flex items-center space-x-1.5 cursor-pointer"
            onClick={() => alert("Asset registration modal: Use API endpoint /api/v1/assets to register new targets.")}
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Asset</span>
          </button>
        </div>
      </div>

      <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-xs">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
            <tr>
              <th className="px-6 py-3.5">Asset Name</th>
              <th className="px-6 py-3.5">Target Scope</th>
              <th className="px-6 py-3.5">Target Type</th>
              <th className="px-6 py-3.5">Criticality</th>
              <th className="px-6 py-3.5">Environment</th>
              <th className="px-6 py-3.5">Network Zone</th>
              <th className="px-6 py-3.5">Authorization Scope</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-slate-700 dark:text-slate-300">
            {filteredAssets.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-8 text-center text-slate-400">
                  <Server className="w-8 h-8 text-slate-300 dark:text-slate-600 mx-auto mb-2" />
                  <span>No assets registered or matching the filter.</span>
                </td>
              </tr>
            ) : (
              filteredAssets.map(a => (
                <tr key={a.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition">
                  <td className="px-6 py-3.5 font-bold text-slate-900 dark:text-white">{a.name}</td>
                  <td className="px-6 py-3.5 font-mono text-indigo-600 dark:text-indigo-400 font-medium">{a.target_value}</td>
                  <td className="px-6 py-3.5 uppercase text-[10px] font-bold text-slate-500">{a.target_type}</td>
                  <td className="px-6 py-3.5">
                    <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider ${
                      criticalityClass[a.criticality] || 'bg-slate-100 text-slate-600'
                    }`}>
                      {a.criticality}
                    </span>
                  </td>
                  <td className="px-6 py-3.5 capitalize">{a.environment}</td>
                  <td className="px-6 py-3.5 capitalize">{a.network_zone}</td>
                  <td className="px-6 py-3.5">
                    <span className="inline-flex items-center space-x-1 text-emerald-600 dark:text-emerald-400 font-semibold bg-emerald-500/10 px-2 py-0.5 rounded">
                      <ShieldCheck className="w-3 h-3" />
                      <span>Approved Scope</span>
                    </span>
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
