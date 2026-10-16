import React, { useState, useEffect } from 'react';

export const WebSecurity: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/v1/findings?limit=100')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          setFindings(data.filter(f => f.detection_method.includes('http') || f.detection_method.includes('cors') || f.detection_method.includes('endpoint') || f.title.toLowerCase().includes('http') || f.title.toLowerCase().includes('web')));
        }
      })
      .catch(err => console.error(err));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-white">Web Application & API Security</h2>
          <p className="text-xs text-slate-400">Passive security headers, CORS verification, OpenAPI schema mapping, and endpoint probing</p>
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 font-semibold uppercase">
            <tr>
              <th className="px-6 py-3">Severity</th>
              <th className="px-6 py-3">Issue Title</th>
              <th className="px-6 py-3">Component / URL</th>
              <th className="px-6 py-3">Method</th>
              <th className="px-6 py-3">Evidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2937] text-slate-300">
            {findings.length === 0 ? (
              <tr><td colSpan={5} className="px-6 py-4 text-center text-slate-500">No web security findings identified yet.</td></tr>
            ) : (
              findings.map(f => (
                <tr key={f.id}>
                  <td className="px-6 py-3 font-bold text-amber-400">{f.severity}</td>
                  <td className="px-6 py-3 font-semibold text-white">{f.title}</td>
                  <td className="px-6 py-3 font-mono text-indigo-400">{f.affected_component}</td>
                  <td className="px-6 py-3 text-slate-400">{f.detection_method}</td>
                  <td className="px-6 py-3 text-slate-300 truncate max-w-xs">{f.evidence || 'N/A'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
