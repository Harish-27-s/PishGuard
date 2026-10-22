import React from 'react';
import { Shield, ShieldAlert, Database, BookOpen, MessageSquare, Globe, PhoneCall } from 'lucide-react';

interface NavbarProps {
  activeTab: 'url' | 'message' | 'database' | 'guide';
  setActiveTab: (tab: 'url' | 'message' | 'database' | 'guide') => void;
  dbCount: number;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, dbCount }) => {
  return (
    <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Project Title */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('url')}>
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-amber-500 to-red-600 flex items-center justify-center shadow-lg shadow-amber-500/20 text-white">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-xl tracking-tight text-white">PhishGuard</span>
                <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                  India Citizen Shield
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Explainable phishing & spoofing detection · Seva First Initiative
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center space-x-1 sm:space-x-2">
            <button
              onClick={() => setActiveTab('url')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'url'
                  ? 'bg-amber-500 text-slate-950 font-semibold shadow'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Globe className="w-4 h-4" />
              <span>URL Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('message')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'message'
                  ? 'bg-amber-500 text-slate-950 font-semibold shadow'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <MessageSquare className="w-4 h-4" />
              <span>SMS / Message</span>
            </button>

            <button
              onClick={() => setActiveTab('database')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'database'
                  ? 'bg-amber-500 text-slate-950 font-semibold shadow'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <Database className="w-4 h-4" />
              <span className="hidden md:inline">Threat DB</span>
              <span className="text-xs px-1.5 py-0.2 rounded-full bg-slate-800 text-amber-400 font-mono">
                {dbCount > 1000 ? `${(dbCount / 1000).toFixed(1)}k` : dbCount}
              </span>
            </button>

            <button
              onClick={() => setActiveTab('guide')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition ${
                activeTab === 'guide'
                  ? 'bg-amber-500 text-slate-950 font-semibold shadow'
                  : 'text-slate-300 hover:text-white hover:bg-slate-800'
              }`}
            >
              <BookOpen className="w-4 h-4" />
              <span className="hidden md:inline">Safety Guide</span>
            </button>
          </nav>

          {/* Citizen Helpline Quick Badge */}
          <div className="hidden lg:flex items-center space-x-2 pl-4 border-l border-slate-800">
            <div className="flex items-center space-x-2 bg-red-950/40 border border-red-900/60 text-red-300 px-3 py-1 rounded-full text-xs">
              <PhoneCall className="w-3.5 h-3.5 text-red-400 animate-pulse" />
              <span>Cyber Helpline: <strong className="font-bold text-white tracking-wider">1930</strong></span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
