import { useState, useEffect } from 'react';
import { Dashboard } from './pages/Dashboard';
import { Assets } from './pages/Assets';
import { Scans } from './pages/Scans';
import { Findings } from './pages/Findings';
import { WebSecurity } from './pages/WebSecurity';
import { NetworkSecurity } from './pages/NetworkSecurity';
import { NetworkDevices } from './pages/NetworkDevices';
import { Compliance } from './pages/Compliance';
import { Reports } from './pages/Reports';
import { Admin } from './pages/Admin';

type TabKey = 
  | 'dashboard'
  | 'assets'
  | 'scans'
  | 'findings'
  | 'webapp'
  | 'network'
  | 'devices'
  | 'compliance'
  | 'reports'
  | 'admin';

interface TabItem {
  id: TabKey;
  label: string;
  badge?: string;
}

const TABS: TabItem[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'assets', label: 'Asset Inventory' },
  { id: 'scans', label: 'Scan Operations' },
  { id: 'findings', label: 'Vulnerabilities' },
  { id: 'webapp', label: 'Web & API Security' },
  { id: 'network', label: 'Network Security' },
  { id: 'devices', label: 'Network Devices' },
  { id: 'compliance', label: 'Compliance Center' },
  { id: 'reports', label: 'Reporting Center' },
  { id: 'admin', label: 'Administration' },
];

export default function App() {
  const [activeTab, setActiveTab] = useState<TabKey>('dashboard');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
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

  const toggleTheme = () => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'));
  };

  const isDark = theme === 'dark';

  return (
    <div className={`flex min-h-screen ${isDark ? 'bg-[#0a0f1d] text-slate-100' : 'bg-slate-50 text-slate-900'}`}>
      {/* Sidebar */}
      <aside className={`w-64 border-r p-5 flex flex-col justify-between ${
        isDark ? 'bg-[#111827] border-[#1f2937]' : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div>
          <div className="flex items-center justify-between mb-8">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center font-bold text-white shadow-lg">VF</div>
              <div>
                <span className={`font-bold text-base tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>VulnForge</span>
                <span className="text-[10px] ml-1 bg-indigo-500/20 text-indigo-400 px-1.5 py-0.5 rounded border border-indigo-500/30">ENT</span>
              </div>
            </div>
            {/* Theme Toggle Button */}
            <button
              onClick={toggleTheme}
              title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
              className={`p-1.5 rounded-lg border text-xs transition ${
                isDark 
                  ? 'bg-slate-800 border-slate-700 text-amber-400 hover:bg-slate-700' 
                  : 'bg-slate-100 border-slate-200 text-indigo-600 hover:bg-slate-200'
              }`}
            >
              {isDark ? '☀️' : '🌙'}
            </button>
          </div>

          <nav className="space-y-1 text-sm">
            {TABS.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full text-left px-3 py-2 rounded-lg transition flex items-center justify-between ${
                  activeTab === tab.id
                    ? isDark
                      ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 font-semibold'
                      : 'bg-indigo-50 text-indigo-700 border border-indigo-200 font-semibold'
                    : isDark
                      ? 'text-slate-400 hover:text-white hover:bg-slate-800'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                }`}
              >
                <span>{tab.label}</span>
              </button>
            ))}
          </nav>
        </div>

        <div className={`text-xs p-3 rounded-lg border ${
          isDark ? 'bg-slate-900/50 border-[#1f2937] text-slate-500' : 'bg-slate-100 border-slate-200 text-slate-600'
        }`}>
          <div className="font-semibold">VulnForge Enterprise v1.0.0</div>
          <div className="text-[10px] text-emerald-500 mt-0.5">● RHEL 9 / Rocky Linux Ready</div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 p-8 space-y-6 overflow-y-auto">
        <header className={`flex justify-between items-center border-b pb-4 ${
          isDark ? 'border-[#1f2937]' : 'border-slate-200'
        }`}>
          <div>
            <h1 className="text-xl font-bold capitalize">
              {TABS.find(t => t.id === activeTab)?.label}
            </h1>
            <p className="text-xs text-slate-400">Enterprise Vulnerability Assessment & Compliance Operations Console</p>
          </div>
          <a
            href="/dashboard"
            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold rounded-lg text-white shadow transition"
          >
            Launch Standalone Operations Console
          </a>
        </header>

        {/* Tab Renderers */}
        <div className="pt-2">
          {activeTab === 'dashboard' && <Dashboard stats={stats} />}
          {activeTab === 'assets' && <Assets />}
          {activeTab === 'scans' && <Scans />}
          {activeTab === 'findings' && <Findings />}
          {activeTab === 'webapp' && <WebSecurity />}
          {activeTab === 'network' && <NetworkSecurity />}
          {activeTab === 'devices' && <NetworkDevices />}
          {activeTab === 'compliance' && <Compliance />}
          {activeTab === 'reports' && <Reports />}
          {activeTab === 'admin' && <Admin />}
        </div>
      </main>
    </div>
  );
}
