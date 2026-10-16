import React, { useState, useEffect } from 'react';

export const NetworkSecurity: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/v1/findings?limit=100')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          setFindings(data.filter(f => f.detection_method.includes('tcp') || f.detection_method.includes('ssh') || f.detection_method.includes('winrm') || f.port || f.title.toLowerCase().includes('port') || f.title.toLowerCase().includes('ssh') || f.title.toLowerCase().includes('windows')));
        }
      })
      .catch(err => console.error(err));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-white">Network & Server Security</h2>
          <p className="text-xs text-slate-400">TCP port discovery, service banner inventory, Linux SSH audits, and Windows WinRM baselines</p>
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 font-semibold uppercase">
            <tr>
              <th className="px-6 py-3">Severity</th>
              <th className="px-6 py-3">Service / Vulnerability</th>
              <th className="px-6 py-3">Asset Host</th>
              <th className="px-6 py-3">Port / Proto</th>
              <th className="px-6 py-3">Detection Method</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2937] text-slate-300">
            {findings.length === 0 ? (
              <tr><td colSpan={5} className="px-6 py-4 text-center text-slate-500">No network security findings identified yet.</td></tr>
            ) : (
              findings.map(f => (
                <tr key={f.id}>
                  <td className="px-6 py-3 font-bold text-indigo-400">{f.severity}</td>
                  <td className="px-6 py-3 font-semibold text-white">{f.title}</td>
                  <td className="px-6 py-3 text-slate-300">{f.asset_name || f.target_value || 'Host'}</td>
                  <td className="px-6 py-3 font-mono text-slate-400">{f.port ? `${f.port}/${f.protocol}` : 'Host'}</td>
                  <td className="px-6 py-3 text-slate-400">{f.detection_method}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
