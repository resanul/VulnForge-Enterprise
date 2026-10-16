import React, { useState, useEffect } from 'react';

export const NetworkDevices: React.FC = () => {
  const [findings, setFindings] = useState<any[]>([]);

  useEffect(() => {
    fetch('/api/v1/findings?limit=100')
      .then(res => res.json())
      .then(data => {
        if (Array.isArray(data)) {
          setFindings(data.filter(f => 
            f.detection_method?.includes('device') ||
            f.affected_component?.toLowerCase().includes('vty') ||
            f.affected_component?.toLowerCase().includes('snmp') ||
            f.affected_component?.toLowerCase().includes('router') ||
            f.title?.toLowerCase().includes('cisco') ||
            f.title?.toLowerCase().includes('router') ||
            f.title?.toLowerCase().includes('switch') ||
            f.title?.toLowerCase().includes('snmp') ||
            f.title?.toLowerCase().includes('syslog') ||
            f.title?.toLowerCase().includes('ntp')
          ));
        }
      })
      .catch(err => console.error(err));
  }, []);

  const telnetCount = findings.filter(f => f.title?.toLowerCase().includes('telnet')).length;
  const snmpCount = findings.filter(f => f.title?.toLowerCase().includes('snmp')).length;
  const syslogCount = findings.filter(f => f.title?.toLowerCase().includes('syslog') || f.title?.toLowerCase().includes('ntp')).length;

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-lg font-bold text-white">Network Device & Appliance Security</h2>
          <p className="text-xs text-slate-400">Cisco IOS, Juniper JunOS, and FortiOS configuration hardening & SNMP security posture</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Audited Devices</span>
          <div className="text-3xl font-extrabold text-white mt-2">{new Set(findings.map(f => f.affected_component)).size}</div>
          <p className="text-xs text-slate-400 mt-2">Appliance targets</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-red-400 uppercase tracking-wider">Cleartext Telnet / HTTP</span>
          <div className="text-3xl font-extrabold text-red-500 mt-2">{telnetCount}</div>
          <p className="text-xs text-slate-400 mt-2">VTY lines exposed</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-amber-400 uppercase tracking-wider">SNMP Misconfigurations</span>
          <div className="text-3xl font-extrabold text-amber-500 mt-2">{snmpCount}</div>
          <p className="text-xs text-slate-400 mt-2">v1/v2c default communities</p>
        </div>
        <div className="bg-[#111827] border border-[#1f2937] p-5 rounded-xl">
          <span className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Syslog / NTP Missing</span>
          <div className="text-3xl font-extrabold text-blue-400 mt-2">{syslogCount}</div>
          <p className="text-xs text-slate-400 mt-2">Audit trail deficiencies</p>
        </div>
      </div>

      <div className="bg-[#111827] border border-[#1f2937] rounded-xl overflow-hidden">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-900/60 text-slate-400 font-semibold uppercase">
            <tr>
              <th className="px-6 py-3">Severity</th>
              <th className="px-6 py-3">Audit Rule Title</th>
              <th className="px-6 py-3">Device / Interface</th>
              <th className="px-6 py-3">Configuration Evidence</th>
              <th className="px-6 py-3">Remediation</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1f2937] text-slate-300">
            {findings.length === 0 ? (
              <tr><td colSpan={5} className="px-6 py-4 text-center text-slate-500">No network device audit findings recorded. Run an appliance configuration audit.</td></tr>
            ) : (
              findings.map(f => (
                <tr key={f.id}>
                  <td className="px-6 py-3 font-bold text-amber-400">{f.severity}</td>
                  <td className="px-6 py-3 font-semibold text-white">{f.title}</td>
                  <td className="px-6 py-3 font-mono text-indigo-400">{f.affected_component}</td>
                  <td className="px-6 py-3 text-slate-300 truncate max-w-xs">{f.evidence || 'N/A'}</td>
                  <td className="px-6 py-3 text-slate-400 truncate max-w-xs">{f.remediation || 'N/A'}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
