import React, { useState, useEffect } from 'react';
import { Bot, Key, ShieldAlert, CheckCircle, RefreshCw, Cpu } from 'lucide-react';

export const IdentityAndAISecurity: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchFindings = () => {
    setIsLoading(true);
    fetch('/api/v1/findings?limit=100')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          setFindings(data.filter(f => 
            f.detection_method?.toLowerCase().includes('ad') ||
            f.detection_method?.toLowerCase().includes('ldap') ||
            f.detection_method?.toLowerCase().includes('kerberos') ||
            f.detection_method?.toLowerCase().includes('emerging') ||
            f.detection_method?.toLowerCase().includes('malware') ||
            f.affected_component?.toLowerCase().includes('ldap') ||
            f.affected_component?.toLowerCase().includes('kerberos') ||
            f.affected_component?.toLowerCase().includes('ollama') ||
            f.affected_component?.toLowerCase().includes('vllm') ||
            f.affected_component?.toLowerCase().includes('flowise') ||
            f.title?.toLowerCase().includes('active directory') ||
            f.title?.toLowerCase().includes('ldap') ||
            f.title?.toLowerCase().includes('kerberos') ||
            f.title?.toLowerCase().includes('smb signing') ||
            f.title?.toLowerCase().includes('ollama') ||
            f.title?.toLowerCase().includes('ai') ||
            f.title?.toLowerCase().includes('llm') ||
            f.title?.toLowerCase().includes('webshell') ||
            f.title?.toLowerCase().includes('miner')
          ));
        }
      })
      .catch(err => console.error(err))
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    fetchFindings();
  }, []);

  const adIssues = findings.filter(f => 
    f.title?.toLowerCase().includes('directory') || 
    f.title?.toLowerCase().includes('ldap') || 
    f.title?.toLowerCase().includes('kerberos') ||
    f.title?.toLowerCase().includes('smb')
  ).length;

  const aiExposures = findings.filter(f => 
    f.title?.toLowerCase().includes('ai') || 
    f.title?.toLowerCase().includes('ollama') || 
    f.title?.toLowerCase().includes('vllm') ||
    f.title?.toLowerCase().includes('llm')
  ).length;

  const malwareCount = findings.filter(f => 
    f.title?.toLowerCase().includes('webshell') || 
    f.title?.toLowerCase().includes('miner') ||
    f.detection_method?.toLowerCase().includes('malware')
  ).length;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center space-x-2">
            <Bot className="w-5 h-5 text-indigo-500" />
            <span>Identity, Active Directory & Emerging AI Security</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Active Directory LDAP/Kerberos policy audit, exposed LLM inference APIs (Ollama, vLLM), and malware indicators
          </p>
        </div>
        <button
          onClick={fetchFindings}
          className="p-2 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 hover:text-indigo-500 transition shadow-xs"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0F172A] shadow-xs">
          <div className="flex items-center space-x-2 text-indigo-500 mb-2">
            <Key className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Active Directory</span>
          </div>
          <div className="text-3xl font-extrabold text-slate-900 dark:text-white">{adIssues}</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">LDAP signing & Kerberos policies</p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0F172A] shadow-xs">
          <div className="flex items-center space-x-2 text-purple-500 mb-2">
            <Cpu className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Exposed AI/LLM</span>
          </div>
          <div className="text-3xl font-extrabold text-slate-900 dark:text-white">{aiExposures}</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Ollama, vLLM, Flowise ports</p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0F172A] shadow-xs">
          <div className="flex items-center space-x-2 text-red-500 mb-2">
            <ShieldAlert className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Malware / Shells</span>
          </div>
          <div className="text-3xl font-extrabold text-red-500">{malwareCount}</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Web shells & cryptominer regex</p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0F172A] shadow-xs">
          <div className="flex items-center space-x-2 text-emerald-500 mb-2">
            <CheckCircle className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Total Audited</span>
          </div>
          <div className="text-3xl font-extrabold text-emerald-500">{findings.length}</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Specialized risk findings</p>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0F172A] shadow-xs overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 dark:text-slate-400 font-semibold uppercase border-b border-slate-200 dark:border-slate-800">
            <tr>
              <th className="px-6 py-3.5">Severity</th>
              <th className="px-6 py-3.5">Vulnerability / Exposure</th>
              <th className="px-6 py-3.5">Component / Port</th>
              <th className="px-6 py-3.5">Engine Method</th>
              <th className="px-6 py-3.5">Evidence & Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-600 dark:text-slate-300">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-400 dark:text-slate-500">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <CheckCircle className="w-8 h-8 text-emerald-500/70" />
                    <span>No Active Directory, AI/LLM, or malware indicator risks detected.</span>
                  </div>
                </td>
              </tr>
            ) : (
              findings.map(f => (
                <tr key={f.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30 transition">
                  <td className="px-6 py-3">
                    <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                      f.severity === 'Critical' ? 'bg-red-500/10 text-red-500 border border-red-500/20' :
                      f.severity === 'High' ? 'bg-orange-500/10 text-orange-500 border border-orange-500/20' :
                      f.severity === 'Medium' ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20' :
                      'bg-blue-500/10 text-blue-500 border border-blue-500/20'
                    }`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-6 py-3 font-semibold text-slate-900 dark:text-white">{f.title}</td>
                  <td className="px-6 py-3 font-mono text-indigo-500">{f.affected_component}</td>
                  <td className="px-6 py-3 text-slate-400 capitalize">{f.detection_method}</td>
                  <td className="px-6 py-3 text-slate-500 dark:text-slate-400 truncate max-w-xs">{f.evidence || 'N/A'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
