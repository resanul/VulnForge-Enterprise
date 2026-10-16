import React, { useState, useEffect } from 'react';

export const Compliance: React.FC = () => {
  const [results, setResults] = useState<any[]>([]);
  const [filterFramework, setFilterFramework] = useState<string>('all');

  useEffect(() => {
    fetch('/api/v1/compliance/results')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) setResults(data);
      })
      .catch(err => console.error(err));
  }, []);

  const filtered = filterFramework === 'all' 
    ? results 
    : results.filter(r => r.framework?.toLowerCase().includes(filterFramework.toLowerCase()));

  const passCount = filtered.filter(r => r.status?.toLowerCase() === 'pass').length;
  const failCount = filtered.filter(r => r.status?.toLowerCase() === 'fail').length;
  const passRate = filtered.length > 0 ? Math.round((passCount / filtered.length) * 100) : 100;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-white">Compliance Center & Benchmarking</h2>
          <p className="text-xs text-slate-400">Continuous audit mapping against CIS Benchmarks, PCI-DSS 4.0, ISO 27001, and HIPAA</p>
        </div>
        <div className="flex space-x-2">
          {['all', 'cis', 'pci-dss', 'iso27001', 'hipaa'].map(fw => (
            <button
              key={fw}
              onClick={() => setFilterFramework(fw)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase transition ${
                filterFramework === fw 
                  ? 'bg-indigo-600 text-white shadow' 
                  : 'bg-slate-800 text-slate-400 hover:text-white'
              }`}
            >
              {fw}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Evaluated Controls</span>
          <div className="text-3xl font-extrabold text-white mt-2">{filtered.length}</div>
          <p className="text-xs text-slate-400 mt-2">Active policy rules</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-emerald-400 uppercase tracking-wider">Passed Controls</span>
          <div className="text-3xl font-extrabold text-emerald-500 mt-2">{passCount}</div>
          <p className="text-xs text-slate-400 mt-2">Compliant controls</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-red-400 uppercase tracking-wider">Failed Controls</span>
          <div className="text-3xl font-extrabold text-red-500 mt-2">{failCount}</div>
          <p className="text-xs text-slate-400 mt-2">Requires remediation</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wider">Overall Posture</span>
          <div className="text-3xl font-extrabold text-indigo-400 mt-2">{passRate}%</div>
          <p className="text-xs text-slate-400 mt-2">Compliance adherence rate</p>
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 font-semibold uppercase">
            <tr>
              <th className="px-6 py-3">Framework</th>
              <th className="px-6 py-3">Rule ID</th>
              <th className="px-6 py-3">Control Title</th>
              <th className="px-6 py-3">Status</th>
              <th className="px-6 py-3">Severity</th>
              <th className="px-6 py-3">Observed vs Expected</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2937] text-slate-300">
            {filtered.length === 0 ? (
              <tr><td colSpan={6} className="px-6 py-4 text-center text-slate-500">No compliance evaluation records found.</td></tr>
            ) : (
              filtered.map(r => (
                <tr key={r.id}>
                  <td className="px-6 py-3 font-semibold text-indigo-400">{r.framework}</td>
                  <td className="px-6 py-3 font-mono text-slate-300">{r.rule_id}</td>
                  <td className="px-6 py-3 font-medium text-white">{r.title}</td>
                  <td className="px-6 py-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      r.status?.toLowerCase() === 'pass' 
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' 
                        : 'bg-red-500/20 text-red-400 border border-red-500/30'
                    }`}>
                      {r.status}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-slate-400">{r.severity}</td>
                  <td className="px-6 py-3 text-slate-400 font-mono text-[11px]">
                    Observed: {r.observed_value || 'None'} / Expected: {r.expected_value || 'Compliant'}
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
