import React, { useState, useEffect } from 'react';

export const Reports: React.FC = () => {
  const [reports, setReports] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [selectedJobId, setSelectedJobId] = useState<string>('');
  const [reportType, setReportType] = useState<string>('technical');
  const [reportFormat, setReportFormat] = useState<string>('html');
  const [isGenerating, setIsGenerating] = useState<boolean>(false);

  const fetchReports = () => {
    fetch('/api/v1/reports')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) setReports(data);
      })
      .catch(err => console.error(err));
  };

  useEffect(() => {
    fetchReports();
    fetch('/api/v1/scans')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          setScans(data);
          if (data.length > 0) setSelectedJobId(String(data[0].id));
        }
      })
      .catch(err => console.error(err));
  }, []);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedJobId) return;
    setIsGenerating(true);
    try {
      const res = await fetch('/api/v1/reports/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          job_id: parseInt(selectedJobId, 10),
          report_type: reportType,
          report_format: reportFormat
        })
      });
      if (res.ok) {
        fetchReports();
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-white">Reporting Center</h2>
          <p className="text-xs text-slate-400">Generate executive, technical, and regulatory compliance audit reports (PDF, HTML, CSV, JSON)</p>
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] p-6 rounded-xl">
        <h3 className="text-sm font-bold text-white mb-4">Export Assessment Report</h3>
        <form onSubmit={handleGenerate} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1">Select Scan Job</label>
            <select
              value={selectedJobId}
              onChange={e => setSelectedJobId(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200"
            >
              {scans.map(s => (
                <option key={s.id} value={s.id}>#{s.id} - {s.target} ({s.status})</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1">Report Perspective</label>
            <select
              value={reportType}
              onChange={e => setReportType(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200"
            >
              <option value="technical">Technical Assessment</option>
              <option value="executive">Executive Board Summary</option>
              <option value="compliance">Compliance Audit Report</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-1">Format</label>
            <select
              value={reportFormat}
              onChange={e => setReportFormat(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-200"
            >
              <option value="html">Interactive HTML</option>
              <option value="pdf">Formal PDF Report</option>
              <option value="json">Machine-Readable JSON</option>
              <option value="csv">Tabular CSV</option>
            </select>
          </div>
          <div>
            <button
              type="submit"
              disabled={isGenerating || !selectedJobId}
              className="w-full px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-semibold text-xs rounded-lg shadow transition"
            >
              {isGenerating ? 'Compiling Report...' : 'Generate Report'}
            </button>
          </div>
        </form>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 font-semibold uppercase">
            <tr>
              <th className="px-6 py-3">Report ID</th>
              <th className="px-6 py-3">Title</th>
              <th className="px-6 py-3">Type</th>
              <th className="px-6 py-3">Format</th>
              <th className="px-6 py-3">Generated</th>
              <th className="px-6 py-3">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2937] text-slate-300">
            {reports.length === 0 ? (
              <tr><td colSpan={6} className="px-6 py-4 text-center text-slate-500">No reports generated yet. Use the form above to build an assessment deliverable.</td></tr>
            ) : (
              reports.map(r => (
                <tr key={r.id}>
                  <td className="px-6 py-3 font-mono text-slate-400">#{r.id}</td>
                  <td className="px-6 py-3 font-semibold text-white">{r.title}</td>
                  <td className="px-6 py-3 capitalize text-indigo-400">{r.report_type}</td>
                  <td className="px-6 py-3 uppercase font-bold text-slate-300">{r.report_format}</td>
                  <td className="px-6 py-3 text-slate-400">{new Date(r.created_at * 1000).toLocaleString()}</td>
                  <td className="px-6 py-3">
                    <a
                      href={`/api/v1/reports/${r.id}/download`}
                      download
                      className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-indigo-400 border border-slate-700 rounded font-semibold text-[11px]"
                    >
                      Download
                    </a>
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
