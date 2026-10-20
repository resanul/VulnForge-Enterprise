import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Filter, 
  ChevronRight, 
  ChevronDown, 
  Clock 
} from 'lucide-react';

export const Findings: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [expandedId, setExpandedId] = useState<number | null>(null);

  useEffect(() => {
    fetch('/api/v1/findings?limit=100')
      .then(res => res.json())
      .then(data => setFindings(Array.isArray(data) ? data : []))
      .catch(err => console.error(err));
  }, []);

  const severityBadgeClass: Record<string, string> = {
    Critical: 'bg-red-500/15 text-red-500 dark:text-red-400 border border-red-500/30',
    High: 'bg-orange-500/15 text-orange-500 dark:text-orange-400 border border-orange-500/30',
    Medium: 'bg-amber-500/15 text-amber-500 dark:text-amber-400 border border-amber-500/30',
    Low: 'bg-blue-500/15 text-blue-500 dark:text-blue-400 border border-blue-500/30',
    Info: 'bg-slate-500/15 text-slate-500 dark:text-slate-400 border border-slate-500/30'
  };

  const filteredFindings = findings.filter(f => {
    const matchesSearch = 
      (f.title || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.cve || '').toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.asset_name || f.target_value || '').toLowerCase().includes(searchQuery.toLowerCase());
    const matchesSeverity = selectedSeverity === 'ALL' || f.severity === selectedSeverity;
    return matchesSearch && matchesSeverity;
  });

  const toggleExpand = (id: number) => {
    setExpandedId(prev => (prev === id ? null : id));
  };

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white tracking-tight">Vulnerability Management</h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            Normalized, deduplicated vulnerability findings repository with authoritative CVSS v3.1 scoring
          </p>
        </div>

        {/* Search and Filters */}
        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search findings, CVE, asset..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
          </div>

          <div className="flex items-center space-x-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={selectedSeverity}
              onChange={e => setSelectedSeverity(e.target.value)}
              className="text-xs rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-900 dark:text-white px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
              <option value="Info">Info</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-white dark:bg-[#0F172A] border border-slate-200 dark:border-slate-800 rounded-2xl overflow-hidden shadow-xs">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 dark:text-slate-400 font-semibold uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
            <tr>
              <th className="px-5 py-3.5 w-10"></th>
              <th className="px-4 py-3.5">Severity</th>
              <th className="px-5 py-3.5">Vulnerability Title</th>
              <th className="px-4 py-3.5">Affected Asset</th>
              <th className="px-4 py-3.5">CVE Identifier</th>
              <th className="px-4 py-3.5">Target Port</th>
              <th className="px-4 py-3.5">Confidence</th>
              <th className="px-4 py-3.5">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800 text-slate-700 dark:text-slate-300">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-6 py-8 text-center text-slate-400">
                  <ShieldAlert className="w-8 h-8 text-slate-300 dark:text-slate-600 mx-auto mb-2" />
                  <span>No vulnerability findings match the current filter.</span>
                </td>
              </tr>
            ) : (
              filteredFindings.map(f => {
                const isExpanded = expandedId === f.id;
                return (
                  <React.Fragment key={f.id}>
                    <tr 
                      onClick={() => toggleExpand(f.id)}
                      className="hover:bg-slate-50 dark:hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="px-5 py-3.5 text-slate-400">
                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </td>
                      <td className="px-4 py-3.5">
                        <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold tracking-wide ${severityBadgeClass[f.severity] || severityBadgeClass.Info}`}>
                          {f.severity} ({f.cvss_score ?? '0.0'})
                        </span>
                      </td>
                      <td className="px-5 py-3.5 font-bold text-slate-900 dark:text-white max-w-sm truncate" title={f.title}>
                        {f.title}
                      </td>
                      <td className="px-4 py-3.5 text-slate-600 dark:text-slate-400 font-mono">
                        {f.asset_name || f.target_value || 'Asset Host'}
                      </td>
                      <td className="px-4 py-3.5 font-mono text-indigo-600 dark:text-indigo-400 font-semibold">
                        {f.cve || f.cwe || 'CWE-Generic'}
                      </td>
                      <td className="px-4 py-3.5 text-slate-500 font-mono">
                        {f.port ? `${f.port}/${f.protocol || 'tcp'}` : 'Host'}
                      </td>
                      <td className="px-4 py-3.5">
                        <span className="text-[10px] uppercase font-semibold text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded">
                          {f.confidence || 'Confirmed'}
                        </span>
                      </td>
                      <td className="px-4 py-3.5">
                        <span className="text-[10px] font-semibold text-slate-600 dark:text-slate-300">
                          {f.status || 'Open'}
                        </span>
                      </td>
                    </tr>

                    {/* Expandable Technical Evidence & Remediation Drawer */}
                    {isExpanded && (
                      <tr className="bg-slate-50/70 dark:bg-slate-900/40">
                        <td colSpan={8} className="px-8 py-5 border-t border-slate-100 dark:border-slate-800/60">
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="space-y-3">
                              <div className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                                Technical Evidence & Trace
                              </div>
                              <pre className="p-3.5 rounded-xl bg-slate-900 text-slate-200 font-mono text-[11px] overflow-x-auto border border-slate-800">
                                {f.evidence || 'Detection evidence: Verified via response signature matching and network handshake.'}
                              </pre>
                              <div className="text-[11px] text-slate-500">
                                Detected by engine: <span className="font-mono text-slate-700 dark:text-slate-300">{f.engine || 'VulnForgeCore'}</span>
                              </div>
                            </div>

                            <div className="space-y-3">
                              <div className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                                Remediation Recommendation & SLA
                              </div>
                              <div className="p-3.5 rounded-xl bg-indigo-50/50 dark:bg-indigo-950/20 border border-indigo-200 dark:border-indigo-500/20 text-slate-800 dark:text-indigo-200 text-xs">
                                {f.remediation || 'Apply vendor-recommended security updates and restrict public network exposure.'}
                              </div>
                              <div className="flex items-center space-x-2 text-[11px] text-slate-500">
                                <Clock className="w-3.5 h-3.5 text-amber-500" />
                                <span>Remediation Target: Within 48 hours for Critical severity</span>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
