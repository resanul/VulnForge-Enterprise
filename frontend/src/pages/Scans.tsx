import React, { useState, useEffect } from 'react';
import { Radar, Play } from 'lucide-react';

export const Scans: React.FC = () => {
  const [jobs, setJobs] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/v1/scans/jobs?limit=50')
      .then(res => res.json())
      .then(data => setJobs(Array.isArray(data) ? data : []))
      .catch(err => console.error(err));
  }, []);

  const handleCancel = async (jobId: number) => {
    try {
      await fetch(`/api/v1/scans/jobs/${jobId}/cancel`, { method: 'POST' });
      setJobs(prev => prev.map(j => j.id === jobId ? { ...j, status: 'cancelled' } : j));
    } catch (e) {
      console.error(e);
    }
  };

  const statusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-emerald-500/15 text-emerald-500 border border-emerald-500/30">COMPLETED</span>;
      case 'running':
        return <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-indigo-500/15 text-indigo-400 border border-indigo-500/30 animate-pulse">RUNNING</span>;
      case 'cancelled':
        return <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-amber-500/15 text-amber-500 border border-amber-500/30">CANCELLED</span>;
      case 'failed':
      default:
        return <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-[10px] font-bold bg-red-500/15 text-red-500 border border-red-500/30">FAILED</span>;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">Scan Operations Center</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Durable background execution queue, real-time progress monitoring, cancellation, and multi-engine results
          </p>
        </div>

        <button 
          onClick={() => alert("To launch a scan: Use the Scan Center form or send POST /api/v1/scans/launch with target and profile_id.")}
          className="px-4 py-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-xs font-semibold text-white rounded-xl shadow-xs transition flex items-center space-x-2 cursor-pointer"
        >
          <Play className="w-3.5 h-3.5 fill-current" />
          <span>Launch New Scan</span>
        </button>
      </div>

      <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-xs">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
            <tr>
              <th className="px-6 py-3.5">Job ID</th>
              <th className="px-6 py-3.5">Scan Title</th>
              <th className="px-6 py-3.5">Target Scope</th>
              <th className="px-6 py-3.5">Status</th>
              <th className="px-6 py-3.5">Progress</th>
              <th className="px-6 py-3.5">Findings</th>
              <th className="px-6 py-3.5 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-slate-700 dark:text-slate-300">
            {jobs.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-6 py-8 text-center text-slate-400">
                  <Radar className="w-8 h-8 text-slate-300 dark:text-slate-600 mx-auto mb-2" />
                  <span>No background scan jobs active. Click 'Launch New Scan' to begin.</span>
                </td>
              </tr>
            ) : (
              jobs.map(j => (
                <tr key={j.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition">
                  <td className="px-6 py-3.5 font-mono font-bold text-indigo-600 dark:text-indigo-400">#{j.id}</td>
                  <td className="px-6 py-3.5 font-bold text-slate-900 dark:text-white">{j.title}</td>
                  <td className="px-6 py-3.5 font-mono text-slate-600 dark:text-slate-400">{j.target}</td>
                  <td className="px-6 py-3.5">{statusBadge(j.status)}</td>
                  <td className="px-6 py-3.5">
                    <div className="flex items-center space-x-2">
                      <div className="w-24 bg-slate-200 dark:bg-slate-800 rounded-full h-2 overflow-hidden">
                        <div 
                          className="bg-indigo-600 dark:bg-indigo-500 h-2 rounded-full transition-all duration-300" 
                          style={{ width: `${Math.max(j.progress, 5)}%` }} 
                        />
                      </div>
                      <span className="font-mono text-[10px] text-slate-500">{j.progress}%</span>
                    </div>
                  </td>
                  <td className="px-6 py-3.5 font-mono font-bold text-slate-900 dark:text-white">
                    {j.findings_count || 0}
                  </td>
                  <td className="px-6 py-3.5 text-right">
                    {j.status === 'running' ? (
                      <button
                        onClick={() => handleCancel(j.id)}
                        className="px-2.5 py-1 text-[11px] font-semibold text-red-500 hover:text-red-400 hover:bg-red-500/10 rounded border border-red-500/20 transition cursor-pointer"
                      >
                        Cancel
                      </button>
                    ) : (
                      <span className="text-[11px] text-slate-400">--</span>
                    )}
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
