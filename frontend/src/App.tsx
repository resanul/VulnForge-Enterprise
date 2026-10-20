import { useState, useEffect } from 'react';
import { 
  LayoutDashboard, 
  Server, 
  Radar, 
  ShieldAlert, 
  Globe, 
  Network, 
  Router, 
  CheckSquare, 
  FileText, 
  Settings, 
  Sun, 
  Moon, 
  ShieldCheck,
  ExternalLink,
  Activity,
  Cloud,
  Bot
} from 'lucide-react';
import { Dashboard } from './pages/Dashboard';
import { Assets } from './pages/Assets';
import { Scans } from './pages/Scans';
import { Findings } from './pages/Findings';
import { WebSecurity } from './pages/WebSecurity';
import { NetworkSecurity } from './pages/NetworkSecurity';
import { NetworkDevices } from './pages/NetworkDevices';
import { CloudContainerSecurity } from './pages/CloudContainerSecurity';
import { IdentityAndAISecurity } from './pages/IdentityAndAISecurity';
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
  | 'cloud_container'
  | 'identity_ai'
  | 'compliance'
  | 'reports'
  | 'admin';

interface TabItem {
  id: TabKey;
  label: string;
  icon: any;
  badge?: string;
}

const TABS: TabItem[] = [
  { id: 'dashboard', label: 'Executive Dashboard', icon: LayoutDashboard },
  { id: 'assets', label: 'Asset Inventory', icon: Server },
  { id: 'scans', label: 'Scan Operations', icon: Radar },
  { id: 'findings', label: 'Vulnerability Management', icon: ShieldAlert },
  { id: 'webapp', label: 'Web & API Security', icon: Globe },
  { id: 'network', label: 'Network & Host Security', icon: Network },
  { id: 'devices', label: 'Network Device Auditing', icon: Router },
  { id: 'cloud_container', label: 'Cloud & Container Security', icon: Cloud },
  { id: 'identity_ai', label: 'Identity & AI/LLM Security', icon: Bot },
  { id: 'compliance', label: 'Compliance & CIS Baselines', icon: CheckSquare },
  { id: 'reports', label: 'Reporting & Analytics', icon: FileText },
  { id: 'admin', label: 'Administration & System', icon: Settings },
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
    // Toggle dark class on root document
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [theme]);

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
    <div className={`flex min-h-screen font-sans ${isDark ? 'bg-[#0B0F19] text-slate-100' : 'bg-slate-50 text-slate-900'} transition-colors duration-200`}>
      {/* Sidebar */}
      <aside className={`w-72 border-r p-5 flex flex-col justify-between shrink-0 ${
        isDark ? 'bg-[#0F172A] border-slate-800' : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div>
          {/* Logo & Header */}
          <div className="flex items-center justify-between mb-8 pb-4 border-b border-slate-800/60">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 to-blue-500 flex items-center justify-center font-extrabold text-white shadow-lg shadow-indigo-500/20">
                <ShieldCheck className="w-5 h-5 text-white" />
              </div>
              <div>
                <div className="flex items-center space-x-1.5">
                  <span className={`font-extrabold text-base tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    VulnForge
                  </span>
                  <span className="text-[10px] font-bold bg-indigo-500/20 text-indigo-400 px-1.5 py-0.5 rounded border border-indigo-500/30 uppercase tracking-widest">
                    ENT
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 font-medium">Enterprise VAPT Platform</div>
              </div>
            </div>

            {/* Theme Toggle Button */}
            <button
              onClick={toggleTheme}
              title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
              className={`p-2 rounded-lg border text-xs transition-all duration-200 cursor-pointer focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
                isDark 
                  ? 'bg-slate-800/80 border-slate-700 text-amber-400 hover:bg-slate-700 hover:text-amber-300' 
                  : 'bg-slate-100 border-slate-200 text-slate-600 hover:bg-slate-200 hover:text-indigo-600'
              }`}
            >
              {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
          </div>

          {/* Navigation Links */}
          <nav className="space-y-1.5 text-sm" aria-label="Sidebar Navigation">
            {TABS.map(tab => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`w-full text-left px-3.5 py-2.5 rounded-xl transition-all duration-200 cursor-pointer flex items-center justify-between group focus:outline-none focus:ring-2 focus:ring-indigo-500 ${
                    isActive
                      ? isDark
                        ? 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/40 font-semibold shadow-sm'
                        : 'bg-indigo-50 text-indigo-700 border border-indigo-200 font-semibold shadow-xs'
                      : isDark
                        ? 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                        : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className={`w-4 h-4 transition-colors ${
                      isActive 
                        ? 'text-indigo-400' 
                        : isDark ? 'text-slate-400 group-hover:text-slate-200' : 'text-slate-500 group-hover:text-slate-800'
                    }`} />
                    <span className="truncate">{tab.label}</span>
                  </div>
                  {tab.id === 'findings' && stats.open_findings_by_severity?.Critical > 0 && (
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-red-500/20 text-red-400 border border-red-500/30">
                      {stats.open_findings_by_severity.Critical}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Footer info card */}
        <div className={`text-xs p-3.5 rounded-xl border mt-6 ${
          isDark ? 'bg-slate-900/60 border-slate-800 text-slate-400' : 'bg-slate-50 border-slate-200 text-slate-600'
        }`}>
          <div className="flex items-center justify-between">
            <span className="font-semibold tracking-tight">VulnForge Enterprise</span>
            <span className="text-[10px] font-mono bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded">v1.0.0</span>
          </div>
          <div className="flex items-center space-x-1.5 text-[11px] text-emerald-500 font-medium mt-1.5">
            <Activity className="w-3.5 h-3.5 animate-pulse text-emerald-400" />
            <span>RHEL 9 / Rocky Linux Certified</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 p-8 space-y-6 overflow-y-auto">
        <header className={`flex justify-between items-center border-b pb-5 ${
          isDark ? 'border-slate-800' : 'border-slate-200'
        }`}>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400">Security Operations Console</span>
              <span className="text-slate-500">/</span>
              <span className="text-xs text-slate-400 font-medium">Production Scope</span>
            </div>
            <h1 className="text-2xl font-extrabold tracking-tight mt-1 text-slate-900 dark:text-white">
              {TABS.find(t => t.id === activeTab)?.label}
            </h1>
          </div>
          
          <div className="flex items-center space-x-3">
            <a
              href="/docs"
              target="_blank"
              rel="noreferrer"
              className="px-3 py-2 bg-slate-800/80 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg border border-slate-700 transition flex items-center space-x-1.5"
            >
              <span>API Reference</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
            <a
              href="/dashboard"
              className="px-4 py-2 bg-gradient-to-r from-indigo-600 to-blue-600 hover:from-indigo-500 hover:to-blue-500 text-xs font-semibold rounded-lg text-white shadow-md shadow-indigo-600/20 transition flex items-center space-x-1.5"
            >
              <span>Launch Standalone HUD</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
        </header>

        {/* Tab Renderers */}
        <div className="pt-1">
          {activeTab === 'dashboard' && <Dashboard stats={stats} />}
          {activeTab === 'assets' && <Assets />}
          {activeTab === 'scans' && <Scans />}
          {activeTab === 'findings' && <Findings />}
          {activeTab === 'webapp' && <WebSecurity />}
          {activeTab === 'network' && <NetworkSecurity />}
          {activeTab === 'devices' && <NetworkDevices />}
          {activeTab === 'cloud_container' && <CloudContainerSecurity />}
          {activeTab === 'identity_ai' && <IdentityAndAISecurity />}
          {activeTab === 'compliance' && <Compliance />}
          {activeTab === 'reports' && <Reports />}
          {activeTab === 'admin' && <Admin />}
        </div>
      </main>
    </div>
  );
}
