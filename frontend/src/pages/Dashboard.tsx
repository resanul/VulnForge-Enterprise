import React from 'react';
import { 
  Server, 
  Radar, 
  ShieldAlert, 
  TrendingUp, 
  AlertTriangle, 
  ShieldCheck, 
  CheckCircle2, 
  Clock 
} from 'lucide-react';

interface DashboardProps {
  stats: any;
}

export const Dashboard: React.FC<DashboardProps> = ({ stats }) => {
  const criticalCount = stats.open_findings_by_severity?.Critical ?? 0;
  const highCount = stats.open_findings_by_severity?.High ?? 0;
  const mediumCount = stats.open_findings_by_severity?.Medium ?? 0;
  const lowCount = stats.open_findings_by_severity?.Low ?? 0;
  const infoCount = stats.open_findings_by_severity?.Info ?? 0;
  const totalFindings = criticalCount + highCount + mediumCount + lowCount + infoCount;

  return (
    <div className="space-y-6">
      {/* Top Level Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 p-5 rounded-2xl shadow-xs transition-all hover:border-slate-300 dark:hover:border-slate-700">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Discovered Assets</span>
            <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-500 flex items-center justify-center">
              <Server className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-slate-900 dark:text-white mt-2 font-mono">
            {stats.assets_count || 0}
          </div>
          <div className="flex items-center space-x-1.5 text-xs text-emerald-600 dark:text-emerald-400 mt-2 font-medium">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>100% within approved scope</span>
          </div>
        </div>

        <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 p-5 rounded-2xl shadow-xs transition-all hover:border-slate-300 dark:hover:border-slate-700">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Scans Executed</span>
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-500 flex items-center justify-center">
              <Radar className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-slate-900 dark:text-white mt-2 font-mono">
            {stats.scans_count || 0}
          </div>
          <div className="flex items-center space-x-1.5 text-xs text-indigo-600 dark:text-indigo-400 mt-2 font-medium">
            <Clock className="w-3.5 h-3.5" />
            <span>{stats.active_scans_count || 0} Active Engine Jobs</span>
          </div>
        </div>

        <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 p-5 rounded-2xl shadow-xs transition-all hover:border-slate-300 dark:hover:border-slate-700">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-red-500 dark:text-red-400 uppercase tracking-wider">Critical Exposure</span>
            <div className="w-8 h-8 rounded-lg bg-red-500/10 text-red-500 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-red-600 dark:text-red-500 mt-2 font-mono">
            {criticalCount}
          </div>
          <div className="flex items-center space-x-1.5 text-xs text-red-500 mt-2 font-medium">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Immediate Remediation SLA</span>
          </div>
        </div>

        <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 p-5 rounded-2xl shadow-xs transition-all hover:border-slate-300 dark:hover:border-slate-700">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Exposure Index</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-500 flex items-center justify-center">
              <TrendingUp className="w-4 h-4" />
            </div>
          </div>
          <div className="text-3xl font-extrabold text-slate-900 dark:text-white mt-2 font-mono">
            {stats.critical_exposure_index || 0}
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-2">Weighted composite CVSS v3.1</p>
        </div>
      </div>

      {/* Vulnerability Severity Breakdown & Risk Chart */}
      <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 p-6 rounded-2xl space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-slate-900 dark:text-white tracking-tight">Vulnerability Severity Distribution</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">Total {totalFindings} normalized security findings detected across targets</p>
          </div>
          <span className="text-xs font-mono font-medium bg-slate-100 dark:bg-slate-800 px-2.5 py-1 rounded-md text-slate-600 dark:text-slate-300">
            CVSS v3.1 Scoring
          </span>
        </div>

        {/* Severity Tiles */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          <div className="p-4 rounded-xl bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-500/20 text-center transition hover:border-red-400">
            <div className="text-xs font-bold text-red-600 dark:text-red-400 tracking-wider">CRITICAL</div>
            <div className="text-3xl font-black text-red-600 dark:text-red-500 mt-1 font-mono">{criticalCount}</div>
            <div className="text-[11px] text-red-500/80 mt-1">CVSS 9.0 - 10.0</div>
          </div>

          <div className="p-4 rounded-xl bg-orange-50 dark:bg-orange-950/20 border border-orange-200 dark:border-orange-500/20 text-center transition hover:border-orange-400">
            <div className="text-xs font-bold text-orange-600 dark:text-orange-400 tracking-wider">HIGH</div>
            <div className="text-3xl font-black text-orange-600 dark:text-orange-500 mt-1 font-mono">{highCount}</div>
            <div className="text-[11px] text-orange-500/80 mt-1">CVSS 7.0 - 8.9</div>
          </div>

          <div className="p-4 rounded-xl bg-amber-50 dark:bg-amber-950/20 border border-amber-200 dark:border-amber-500/20 text-center transition hover:border-amber-400">
            <div className="text-xs font-bold text-amber-600 dark:text-amber-400 tracking-wider">MEDIUM</div>
            <div className="text-3xl font-black text-amber-600 dark:text-amber-500 mt-1 font-mono">{mediumCount}</div>
            <div className="text-[11px] text-amber-500/80 mt-1">CVSS 4.0 - 6.9</div>
          </div>

          <div className="p-4 rounded-xl bg-blue-50 dark:bg-blue-950/20 border border-blue-200 dark:border-blue-500/20 text-center transition hover:border-blue-400">
            <div className="text-xs font-bold text-blue-600 dark:text-blue-400 tracking-wider">LOW</div>
            <div className="text-3xl font-black text-blue-600 dark:text-blue-500 mt-1 font-mono">{lowCount}</div>
            <div className="text-[11px] text-blue-500/80 mt-1">CVSS 0.1 - 3.9</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-800/30 border border-slate-200 dark:border-slate-700/30 text-center transition hover:border-slate-400">
            <div className="text-xs font-bold text-slate-600 dark:text-slate-400 tracking-wider">INFORMATIONAL</div>
            <div className="text-3xl font-black text-slate-700 dark:text-slate-300 mt-1 font-mono">{infoCount}</div>
            <div className="text-[11px] text-slate-500 mt-1">Non-exploitable</div>
          </div>
        </div>

        {/* Visual Multi-Segment Severity Bar */}
        <div className="pt-2">
          <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2 flex justify-between">
            <span>Finding Severity Ratio</span>
            <span>{totalFindings > 0 ? `${totalFindings} Active Findings` : 'Clean Baseline'}</span>
          </div>
          <div className="h-3 w-full bg-slate-100 dark:bg-slate-800 rounded-full overflow-hidden flex">
            {totalFindings > 0 ? (
              <>
                <div style={{ width: `${(criticalCount / totalFindings) * 100}%` }} className="bg-red-500 transition-all duration-300" title={`Critical: ${criticalCount}`} />
                <div style={{ width: `${(highCount / totalFindings) * 100}%` }} className="bg-orange-500 transition-all duration-300" title={`High: ${highCount}`} />
                <div style={{ width: `${(mediumCount / totalFindings) * 100}%` }} className="bg-amber-500 transition-all duration-300" title={`Medium: ${mediumCount}`} />
                <div style={{ width: `${(lowCount / totalFindings) * 100}%` }} className="bg-blue-500 transition-all duration-300" title={`Low: ${lowCount}`} />
                <div style={{ width: `${(infoCount / totalFindings) * 100}%` }} className="bg-slate-500 transition-all duration-300" title={`Info: ${infoCount}`} />
              </>
            ) : (
              <div className="w-full bg-emerald-500/50" title="No Vulnerabilities Detected" />
            )}
          </div>
        </div>
      </div>

      {/* Operational Highlights Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 p-6 rounded-2xl">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-emerald-500" />
              <span>Compliance & CIS Baselines</span>
            </h4>
            <span className="text-xs text-emerald-500 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
              86.7% Passing
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
            Active evaluation of CIS Linux Benchmark, CIS Windows Server, and PCI-DSS v4.0 technical controls.
          </p>
          <div className="space-y-2.5 text-xs">
            <div className="flex justify-between items-center p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/40">
              <span className="text-slate-700 dark:text-slate-300 font-medium">CIS Red Hat Enterprise Linux 9 Benchmark</span>
              <span className="text-emerald-500 font-bold">Passed (39/42)</span>
            </div>
            <div className="flex justify-between items-center p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/40">
              <span className="text-slate-700 dark:text-slate-300 font-medium">CIS Microsoft Windows Server 2022</span>
              <span className="text-emerald-500 font-bold">Passed (28/30)</span>
            </div>
            <div className="flex justify-between items-center p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/40">
              <span className="text-slate-700 dark:text-slate-300 font-medium">PCI-DSS v4.0 Network Encryption Controls</span>
              <span className="text-amber-500 font-bold">Needs Review (2)</span>
            </div>
          </div>
        </div>

        <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 p-6 rounded-2xl">
          <div className="flex items-center justify-between mb-4">
            <h4 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center space-x-2">
              <Radar className="w-4 h-4 text-indigo-500" />
              <span>Engine Status & Health</span>
            </h4>
            <span className="text-xs text-indigo-400 font-bold bg-indigo-500/10 px-2 py-0.5 rounded border border-indigo-500/20">
              12 Engines Online
            </span>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
            Modular engine adapters decoupled via process isolation and REST microservices.
          </p>
          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/40 flex items-center justify-between">
              <span className="text-slate-600 dark:text-slate-400">NetworkDiscovery</span>
              <span className="text-emerald-500 text-[10px] font-bold">ONLINE</span>
            </div>
            <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/40 flex items-center justify-between">
              <span className="text-slate-600 dark:text-slate-400">TLSChecker</span>
              <span className="text-emerald-500 text-[10px] font-bold">ONLINE</span>
            </div>
            <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/40 flex items-center justify-between">
              <span className="text-slate-600 dark:text-slate-400">WebSecurity</span>
              <span className="text-emerald-500 text-[10px] font-bold">ONLINE</span>
            </div>
            <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/40 flex items-center justify-between">
              <span className="text-slate-600 dark:text-slate-400">LinuxSSH</span>
              <span className="text-emerald-500 text-[10px] font-bold">ONLINE</span>
            </div>
            <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/40 flex items-center justify-between">
              <span className="text-slate-600 dark:text-slate-400">WindowsWinRM</span>
              <span className="text-emerald-500 text-[10px] font-bold">ONLINE</span>
            </div>
            <div className="p-2 rounded bg-slate-50 dark:bg-slate-800/40 flex items-center justify-between">
              <span className="text-slate-600 dark:text-slate-400">CISCompliance</span>
              <span className="text-emerald-500 text-[10px] font-bold">ONLINE</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
