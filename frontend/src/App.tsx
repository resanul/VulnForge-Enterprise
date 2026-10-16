import React, { useState, useEffect } from 'react';

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'assets' | 'scans' | 'findings' | 'compliance' | 'reports' | 'admin'>('dashboard');
  const [stats, setStats] = useState<any>({
    assets_count: 0,
    scans_count: 0,
    active_scans_count: 0,
    open_findings_by_severity: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
    critical_exposure_index: 0
  });

  useEffect(() => {
    fetch('/api/v1/system/dashboard-stats')
      .then(res => res.json())
      .then(data => setStats(data))
      .catch(err => console.error(err));
  }, []);

  return (
    <div className="flex min-h-screen bg-[#0a0f1d] text-slate-100">
      {/* Sidebar */}
      <aside className="w-64 bg-[#111827] border-r border-[#1f2937] p-5 flex flex-col justify-between">
        <div>
          <div className="flex items-center space-x-3 mb-8">
            <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center font-bold text-white shadow-lg">VF</div>
            <div>
              <span className="font-bold text-base text-white tracking-tight">VulnForge</span>
              <span className="text-[10px] ml-1 bg-indigo-500/20 text-indigo-400 px-1.5 py-0.5 rounded border border-indigo-500/30">ENT</span>
            </div>
          </div>
          <nav className="space-y-1 text-sm">
            {(['dashboard', 'assets', 'scans', 'findings', 'compliance', 'reports', 'admin'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`w-full text-left px-3 py-2 rounded-lg capitalize transition ${
                  activeTab === tab ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 font-semibold' : 'text-slate-400 hover:text-white hover:bg-slate-800'
                }`}
              >
                {tab}
              </button>
            ))}
          </nav>
        </div>
        <div className="text-xs text-slate-500">
          VulnForge Enterprise v1.0.0<br/>RHEL 9 / Rocky Linux Ready
        </div>
      </aside>

      {/* Main Panel */}
      <main className="flex-1 p-8 space-y-6">
        <header className="flex justify-between items-center border-b border-[#1f2937] pb-4">
          <h1 className="text-xl font-bold capitalize">{activeTab} Overview</h1>
          <a
            href="/dashboard"
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold rounded-lg text-white shadow"
          >
            Open Live Interactive Operations Console
          </a>
        </header>

        {/* Dashboard Metrics */}
        {activeTab === 'dashboard' && (
          <div className="grid grid-cols-4 gap-6">
            <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
              <span className="text-xs font-semibold text-slate-400 uppercase">Assets Scoped</span>
              <div className="text-3xl font-extrabold text-white mt-2">{stats.assets_count}</div>
            </div>
            <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
              <span className="text-xs font-semibold text-slate-400 uppercase">Total Scans</span>
              <div className="text-3xl font-extrabold text-white mt-2">{stats.scans_count}</div>
            </div>
            <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
              <span className="text-xs font-semibold text-red-400 uppercase">Critical Vulnerabilities</span>
              <div className="text-3xl font-extrabold text-red-500 mt-2">{stats.open_findings_by_severity?.Critical ?? 0}</div>
            </div>
            <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
              <span className="text-xs font-semibold text-indigo-400 uppercase">Exposure Index</span>
              <div className="text-3xl font-extrabold text-indigo-400 mt-2">{stats.critical_exposure_index}</div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
