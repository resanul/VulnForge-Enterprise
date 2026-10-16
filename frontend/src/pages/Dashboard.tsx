import React from 'react';

interface DashboardProps {
  stats: any;
}

export const Dashboard: React.FC<DashboardProps> = ({ stats }) => {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Discovered Assets</span>
          <div className="text-3xl font-extrabold text-white mt-2">{stats.assets_count || 0}</div>
          <p className="text-xs text-slate-400 mt-2">100% within approved scope</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Scans Executed</span>
          <div className="text-3xl font-extrabold text-white mt-2">{stats.scans_count || 0}</div>
          <p className="text-xs text-emerald-400 mt-2">{stats.active_scans_count || 0} Active Background Jobs</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-red-400 uppercase tracking-wider">Critical Vulnerabilities</span>
          <div className="text-3xl font-extrabold text-red-500 mt-2">{stats.open_findings_by_severity?.Critical ?? 0}</div>
          <p className="text-xs text-slate-400 mt-2">Requires immediate remediation</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wider">Exposure Index</span>
          <div className="text-3xl font-extrabold text-indigo-400 mt-2">{stats.critical_exposure_index || 0}</div>
          <p className="text-xs text-slate-400 mt-2">Weighted composite CVSS v3.1</p>
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] p-6 rounded-xl space-y-4">
        <h3 className="text-sm font-bold text-white uppercase tracking-wider">Vulnerability Severity Distribution</h3>
        <div className="grid grid-cols-5 gap-4">
          <div className="p-4 rounded-lg bg-red-950/20 border border-red-500/20 text-center">
            <div className="text-xs font-semibold text-red-400">CRITICAL</div>
            <div className="text-2xl font-black text-red-500 mt-1">{stats.open_findings_by_severity?.Critical ?? 0}</div>
          </div>
          <div className="p-4 rounded-lg bg-orange-950/20 border border-orange-500/20 text-center">
            <div className="text-xs font-semibold text-orange-400">HIGH</div>
            <div className="text-2xl font-black text-orange-500 mt-1">{stats.open_findings_by_severity?.High ?? 0}</div>
          </div>
          <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-500/20 text-center">
            <div className="text-xs font-semibold text-amber-400">MEDIUM</div>
            <div className="text-2xl font-black text-amber-500 mt-1">{stats.open_findings_by_severity?.Medium ?? 0}</div>
          </div>
          <div className="p-4 rounded-lg bg-blue-950/20 border border-blue-500/20 text-center">
            <div className="text-xs font-semibold text-blue-400">LOW</div>
            <div className="text-2xl font-black text-blue-500 mt-1">{stats.open_findings_by_severity?.Low ?? 0}</div>
          </div>
          <div className="p-4 rounded-lg bg-slate-800/30 border border-slate-700/30 text-center">
            <div className="text-xs font-semibold text-slate-400">INFO</div>
            <div className="text-2xl font-black text-slate-300 mt-1">{stats.open_findings_by_severity?.Info ?? 0}</div>
          </div>
        </div>
      </div>
    </div>
  );
};
