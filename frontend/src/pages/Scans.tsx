import React, { useState, useEffect } from 'react';
import { Radar, Play, X, Terminal, RefreshCw, CheckCircle2 } from 'lucide-react';

export const Scans: React.FC = () => {
  const [jobs, setJobs] = useState<any[]>([]);
  const [profiles, setProfiles] = useState<any[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedJobLogs, setSelectedJobLogs] = useState<any | null>(null);

  // New Scan Form State
  const [target, setTarget] = useState('127.0.0.1');
  const [title, setTitle] = useState('Full Surface Security Audit');
  const [profileId, setProfileId] = useState<number>(1);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const fetchJobs = async () => {
    try {
      const res = await fetch('/api/v1/scans/jobs?limit=50');
      const data = await res.json();
      setJobs(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error(err);
    }
  };

  const fetchProfiles = async () => {
    try {
      const res = await fetch('/api/v1/scans/profiles');
      const data = await res.json();
      if (Array.isArray(data) && data.length > 0) {
        setProfiles(data);
        setProfileId(data[0].id);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchJobs();
    fetchProfiles();
  }, []);

  // Auto-polling for active background jobs
  useEffect(() => {
    const hasActiveJobs = jobs.some(j => j.status === 'running' || j.status === 'pending');
    let interval: any;
    if (hasActiveJobs) {
      interval = setInterval(() => {
        fetchJobs();
      }, 2500);
    }
    return () => clearInterval(interval);
  }, [jobs]);

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target) return;
    setIsSubmitting(true);
    try {
      const res = await fetch('/api/v1/scans/launch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title,
          target: target.trim(),
          profile_id: Number(profileId)
        })
      });
      if (res.ok) {
        setIsModalOpen(false);
        await fetchJobs();
      } else {
        const err = await res.json();
        alert(`Scan Launch Error: ${err.detail || 'Target rejected or out of scope'}`);
      }
    } catch (e: any) {
      alert(`Network error: ${e.message}`);
    } finally {
      setIsSubmitting(false);
    }
  };

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
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">Scan Operations Center</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Durable background execution queue, real-time progress monitoring, cancellation, and multi-engine results
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchJobs}
            title="Refresh Scan Jobs"
            className="p-2 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 text-slate-600 dark:text-slate-300 rounded-xl border border-slate-200 dark:border-slate-700 transition cursor-pointer"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
          <button 
            onClick={() => setIsModalOpen(true)}
            className="px-4 py-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-xs font-semibold text-white rounded-xl shadow-xs transition flex items-center space-x-2 cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>Launch New Scan</span>
          </button>
        </div>
      </div>

      {/* Scans Table */}
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
                  <td className="px-6 py-3.5 text-right space-x-2">
                    <button
                      onClick={() => setSelectedJobLogs(j)}
                      title="View Execution Log"
                      className="p-1 text-slate-500 hover:text-indigo-400 transition"
                    >
                      <Terminal className="w-4 h-4 inline" />
                    </button>
                    {j.status === 'running' && (
                      <button
                        onClick={() => handleCancel(j.id)}
                        className="px-2.5 py-1 text-[11px] font-semibold text-red-500 hover:text-red-400 hover:bg-red-500/10 rounded border border-red-500/20 transition cursor-pointer"
                      >
                        Cancel
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Interactive Modal: Launch Scan */}
      {isModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-lg shadow-2xl p-6 space-y-5 animate-in fade-in duration-200">
            <div className="flex justify-between items-center border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <Radar className="w-5 h-5 text-indigo-500" />
                <h3 className="text-base font-bold text-slate-900 dark:text-white">Launch Vulnerability Scan</h3>
              </div>
              <button onClick={() => setIsModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleLaunchScan} className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Scan Task Title</label>
                <input
                  type="text"
                  value={title}
                  onChange={e => setTitle(e.target.value)}
                  required
                  placeholder="e.g. Infrastructure & Web Surface Audit"
                  className="w-full px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
              </div>

              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Target Host / IP / CIDR / URL</label>
                <input
                  type="text"
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  required
                  placeholder="e.g. 127.0.0.1 or scanme.nmap.org or 192.168.1.0/24"
                  className="w-full px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500"
                />
                <div className="flex space-x-2 mt-1.5 text-[11px] text-slate-400">
                  <span>Quick select:</span>
                  <button type="button" onClick={() => setTarget('127.0.0.1')} className="underline hover:text-indigo-400">127.0.0.1</button>
                  <button type="button" onClick={() => setTarget('scanme.nmap.org')} className="underline hover:text-indigo-400">scanme.nmap.org</button>
                  <button type="button" onClick={() => setTarget('192.168.1.0/28')} className="underline hover:text-indigo-400">Subnet</button>
                </div>
              </div>

              <div>
                <label className="block text-slate-700 dark:text-slate-300 font-semibold mb-1">Assessment Profile</label>
                <select
                  value={profileId}
                  onChange={e => setProfileId(Number(e.target.value))}
                  className="w-full px-3 py-2 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
                >
                  {profiles.length === 0 ? (
                    <option value={1}>Default Full Audit (Network, TLS, Web, Compliance)</option>
                  ) : (
                    profiles.map(p => (
                      <option key={p.id} value={p.id}>{p.name} ({p.categories})</option>
                    ))
                  )}
                </select>
              </div>

              <div className="p-3 rounded-xl bg-indigo-50/50 dark:bg-indigo-950/20 border border-indigo-200 dark:border-indigo-500/20 text-slate-700 dark:text-indigo-200 text-[11px] flex items-start space-x-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                <span>
                  <strong>Strict Scope Enforcement:</strong> Target will be authorized against corporate approved CIDRs before background execution begins.
                </span>
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
                  {isSubmitting ? 'Starting Job...' : 'Start Scan Job'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Execution Log Viewer Modal */}
      {selectedJobLogs && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-2xl shadow-2xl p-6 space-y-4">
            <div className="flex justify-between items-center border-b border-slate-100 dark:border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  Execution Logs: #{selectedJobLogs.id} - {selectedJobLogs.title}
                </h3>
                <span className="text-xs text-slate-400 font-mono">Target: {selectedJobLogs.target}</span>
              </div>
              <button onClick={() => setSelectedJobLogs(null)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 text-emerald-400 font-mono text-xs overflow-y-auto max-h-80 border border-slate-800 whitespace-pre-wrap">
              {selectedJobLogs.log_output || '[INFO] Job initialized. Awaiting engine dispatch...'}
            </pre>
            <div className="flex justify-end">
              <button
                onClick={() => setSelectedJobLogs(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-white rounded-xl"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
