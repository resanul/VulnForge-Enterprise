import React, { useState, useEffect } from 'react';

export const Scans: React.FC = () => {
  const [jobs, setJobs] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/v1/scans/jobs?limit=50')
      .then(res => res.json())
      .then(data => setJobs(Array.isArray(data) ? data : []))
      .catch(err => console.error(err));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-white">Scan Center</h2>
          <p className="text-xs text-slate-400">Multi-engine scanner orchestration, job progress, and execution logs</p>
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 font-semibold uppercase">
            <tr>
              <th className="px-6 py-3">Job ID</th>
              <th className="px-6 py-3">Scan Title</th>
              <th className="px-6 py-3">Target</th>
              <th className="px-6 py-3">Status</th>
              <th className="px-6 py-3">Progress</th>
              <th className="px-6 py-3">Findings</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2937] text-slate-300">
            {jobs.length === 0 ? (
              <tr><td colSpan={6} className="px-6 py-4 text-center text-slate-500">No scan jobs registered yet.</td></tr>
            ) : (
              jobs.map(j => (
                <tr key={j.id}>
                  <td className="px-6 py-3 font-mono font-bold text-indigo-400">#{j.id}</td>
                  <td className="px-6 py-3 font-semibold text-white">{j.title}</td>
                  <td className="px-6 py-3 font-mono text-slate-300">{j.target}</td>
                  <td className="px-6 py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      j.status === 'completed' ? 'bg-emerald-500/20 text-emerald-400' :
                      j.status === 'running' ? 'bg-indigo-500/20 text-indigo-400 animate-pulse' :
                      j.status === 'cancelled' ? 'bg-amber-500/20 text-amber-400' : 'bg-rose-500/20 text-rose-400'
                    }`}>{j.status.toUpperCase()}</span>
                  </td>
                  <td className="px-6 py-3">
                    <div className="w-24 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                      <div className="bg-indigo-500 h-1.5" style={{ width: `${j.progress}%` }}></div>
                    </div>
                  </td>
                  <td className="px-6 py-3 font-bold text-white">{j.findings_count || 0}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
