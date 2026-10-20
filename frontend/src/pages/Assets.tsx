import React, { useState, useEffect } from 'react';
import { Server, Plus, ShieldCheck, Search, X } from 'lucide-react';

export const Assets: React.FC = () => {
  const [assets, setAssets] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Form State
  const [name, setName] = useState('');
  const [targetType, setTargetType] = useState('ip');
  const [targetValue, setTargetValue] = useState('');
  const [criticality, setCriticality] = useState('high');
  const [environment, setEnvironment] = useState('production');
  const [networkZone, setNetworkZone] = useState('corporate');

  const fetchAssets = async () => {
    try {
      const res = await fetch('/api/v1/assets');
      const data = await res.json();
      setAssets(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchAssets();
  }, []);

  const handleAddAsset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name || !targetValue) return;
    setIsSubmitting(true);
    try {
      const res = await fetch('/api/v1/assets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: name.trim(),
          target_type: targetType,
          target_value: targetValue.trim(),
          criticality,
          environment,
          network_zone: networkZone,
          authorized: true
        })
      });
      if (res.ok) {
        setIsModalOpen(false);
        setName('');
        setTargetValue('');
        await fetchAssets();
      } else {
        const err = await res.json();
        alert(`Failed to add asset: ${err.detail || 'Target authorization failed'}`);
      }
    } catch (e: any) {
      alert(`Network error: ${e.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

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
            onClick={() => setIsModalOpen(true)}
            className="px-3.5 py-1.5 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-xs font-semibold text-white rounded-xl shadow-xs transition flex items-center space-x-1.5 cursor-pointer"
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

      {/* Add Asset Modal */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-lg shadow-2xl p-6 space-y-4">
            <div className="flex justify-between items-center border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Server className="w-5 h-5 text-indigo-500" />
                <h3 className="text-base font-bold text-slate-900 dark:text-white">Register Target Asset</h3>
              </div>
              <button onClick={() => setIsModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleAddAsset} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Asset Display Name</label>
                <input
                  type="text"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  required
                  placeholder="e.g. Production Application Gateway"
                  className="w-full px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Target Type</label>
                  <select
                    value={targetType}
                    onChange={e => setTargetType(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="ip">Single IP Address</option>
                    <option value="hostname">Domain / FQDN</option>
                    <option value="cidr">CIDR Subnet Range</option>
                    <option value="url">Web Application URL</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Target Value</label>
                  <input
                    type="text"
                    value={targetValue}
                    onChange={e => setTargetValue(e.target.value)}
                    required
                    placeholder="e.g. 192.168.10.15"
                    className="w-full px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Criticality</label>
                  <select
                    value={criticality}
                    onChange={e => setCriticality(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Environment</label>
                  <select
                    value={environment}
                    onChange={e => setEnvironment(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="production">Production</option>
                    <option value="staging">Staging</option>
                    <option value="development">Internal Lab</option>
                    <option value="dmz">DMZ / Perimeter</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Network Zone</label>
                  <select
                    value={networkZone}
                    onChange={e => setNetworkZone(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  >
                    <option value="corporate">Corporate LAN</option>
                    <option value="dmz">DMZ</option>
                    <option value="cloud_vpc">Cloud VPC</option>
                    <option value="external">External / WAN</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsModalOpen(false)}
                  className="px-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-5 py-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 text-white font-semibold rounded-xl shadow-md transition disabled:opacity-50"
                >
                  {isSubmitting ? 'Registering...' : 'Register Asset'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
