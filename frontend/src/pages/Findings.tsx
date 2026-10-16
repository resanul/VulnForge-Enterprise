import React, { useState, useEffect } from 'react';

export const Findings: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/v1/findings?limit=100')
      .then(res => res.json())
      .then(data => setFindings(Array.isArray(data) ? data : []))
      .catch(err => console.error(err));
  }, []);

  const colors: Record<string, string> = {
    Critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
    High: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    Medium: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
    Low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
    Info: 'bg-slate-700/30 text-slate-400'
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-white">Vulnerability Findings</h2>
          <p className="text-xs text-slate-400">Normalized and deduplicated vulnerability repository with CVSS v3.1 scoring</p>
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 font-semibold uppercase">
            <tr>
              <th className="px-6 py-3">Severity</th>
              <th className="px-6 py-3">Title</th>
              <th className="px-6 py-3">Asset</th>
              <th className="px-6 py-3">CVE / CWE</th>
              <th className="px-6 py-3">Port</th>
              <th className="px-6 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2937] text-slate-300">
            {findings.length === 0 ? (
              <tr><td colSpan={6} className="px-6 py-4 text-center text-slate-500">No vulnerability findings recorded yet.</td></tr>
            ) : (
              findings.map(f => (
                <tr key={f.id}>
                  <td className="px-6 py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${colors[f.severity] || colors.Info}`}>
                      {f.severity} ({f.cvss_score})
                    </span>
                  </td>
                  <td className="px-6 py-3 font-semibold text-white max-w-xs truncate" title={f.title}>{f.title}</td>
                  <td className="px-6 py-3 text-slate-400">{f.asset_name || f.target_value || 'Asset'}</td>
                  <td className="px-6 py-3 font-mono text-slate-300">{f.cve || f.cwe || 'N/A'}</td>
                  <td className="px-6 py-3 text-slate-400">{f.port ? `${f.port}/${f.protocol}` : 'Host'}</td>
                  <td className="px-6 py-3 font-semibold text-slate-300">{f.status}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
