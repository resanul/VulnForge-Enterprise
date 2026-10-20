import React, { useState, useEffect } from 'react';
import { Cloud, Box, ShieldAlert, CheckCircle, RefreshCw } from 'lucide-react';

export const CloudContainerSecurity: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchFindings = () => {
    setIsLoading(true);
    fetch('/api/v1/findings?limit=100')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          setFindings(data.filter(f => 
            f.detection_method?.toLowerCase().includes('container') ||
            f.detection_method?.toLowerCase().includes('cloud') ||
            f.detection_method?.toLowerCase().includes('trivy') ||
            f.affected_component?.toLowerCase().includes('docker') ||
            f.affected_component?.toLowerCase().includes('container') ||
            f.affected_component?.toLowerCase().includes('cloud') ||
            f.affected_component?.toLowerCase().includes('aws') ||
            f.affected_component?.toLowerCase().includes('s3') ||
            f.title?.toLowerCase().includes('container') ||
            f.title?.toLowerCase().includes('docker') ||
            f.title?.toLowerCase().includes('trivy') ||
            f.title?.toLowerCase().includes('cloud') ||
            f.title?.toLowerCase().includes('bucket') ||
            f.title?.toLowerCase().includes('iam')
          ));
        }
      })
      .catch(err => console.error(err))
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    fetchFindings();
  }, []);

  const containerVulns = findings.filter(f => 
    f.affected_component?.toLowerCase().includes('docker') || 
    f.detection_method?.toLowerCase().includes('container') ||
    f.detection_method?.toLowerCase().includes('trivy')
  ).length;

  const cloudMisconfigs = findings.filter(f => 
    f.affected_component?.toLowerCase().includes('cloud') || 
    f.detection_method?.toLowerCase().includes('cloud') ||
    f.title?.toLowerCase().includes('bucket') ||
    f.title?.toLowerCase().includes('iam')
  ).length;

  const criticalCount = findings.filter(f => f.severity === 'Critical').length;
  const highCount = findings.filter(f => f.severity === 'High').length;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-slate-900 dark:text-white flex items-center space-x-2">
            <Cloud className="w-5 h-5 text-indigo-500" />
            <span>Cloud & Container Security</span>
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Aqua Trivy supply-chain image vulnerability scanning, Dockerfile baselines, and AWS/GCP/Azure IAM posture
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
            <Box className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Container Risks</span>
          </div>
          <div className="text-3xl font-extrabold text-slate-900 dark:text-white">{containerVulns}</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Image & package vulnerabilities</p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0F172A] shadow-xs">
          <div className="flex items-center space-x-2 text-cyan-500 mb-2">
            <Cloud className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Cloud Posture</span>
          </div>
          <div className="text-3xl font-extrabold text-slate-900 dark:text-white">{cloudMisconfigs}</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">IAM policies & storage buckets</p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0F172A] shadow-xs">
          <div className="flex items-center space-x-2 text-red-500 mb-2">
            <ShieldAlert className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">Critical Severities</span>
          </div>
          <div className="text-3xl font-extrabold text-red-500">{criticalCount}</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Immediate remediation required</p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0F172A] shadow-xs">
          <div className="flex items-center space-x-2 text-amber-500 mb-2">
            <ShieldAlert className="w-4 h-4" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">High Severities</span>
          </div>
          <div className="text-3xl font-extrabold text-amber-500">{highCount}</div>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">Elevated risk exposures</p>
        </div>
      </div>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800/80 bg-white dark:bg-[#0F172A] shadow-xs overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 dark:bg-slate-900/60 text-slate-500 dark:text-slate-400 font-semibold uppercase border-b border-slate-200 dark:border-slate-800">
            <tr>
              <th className="px-6 py-3.5">Severity</th>
              <th className="px-6 py-3.5">Issue Title</th>
              <th className="px-6 py-3.5">Target / Image</th>
              <th className="px-6 py-3.5">Engine / Tool</th>
              <th className="px-6 py-3.5">Evidence & Context</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 dark:divide-slate-800/60 text-slate-600 dark:text-slate-300">
            {findings.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-400 dark:text-slate-500">
                  <div className="flex flex-col items-center justify-center space-y-2">
                    <CheckCircle className="w-8 h-8 text-emerald-500/70" />
                    <span>No cloud or container misconfigurations detected. Run a Container or Cloud audit profile.</span>
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
