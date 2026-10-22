import React, { useState } from 'react';
import { DetectionResult } from '../types';
import { ShieldCheck, ShieldAlert, AlertTriangle, Database, Cpu, Wrench, Sparkles, Check, Copy, Info, PhoneCall } from 'lucide-react';

interface VerdictCardProps {
  result: DetectionResult;
  inputTarget: string;
}

export const VerdictCard: React.FC<VerdictCardProps> = ({ result, inputTarget }) => {
  const [copied, setCopied] = useState(false);

  const getVerdictStyle = () => {
    switch (result.verdict) {
      case 'Dangerous':
        return {
          border: 'border-red-500/40',
          bg: 'bg-red-950/20',
          badgeBg: 'bg-red-500/20 text-red-400 border-red-500/30',
          barColor: 'bg-red-500',
          icon: <ShieldAlert className="w-8 h-8 text-red-400" />,
          titleColor: 'text-red-400',
        };
      case 'Suspicious':
        return {
          border: 'border-amber-500/40',
          bg: 'bg-amber-950/20',
          badgeBg: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
          barColor: 'bg-amber-500',
          icon: <AlertTriangle className="w-8 h-8 text-amber-400" />,
          titleColor: 'text-amber-400',
        };
      case 'Safe':
      default:
        return {
          border: 'border-emerald-500/40',
          bg: 'bg-emerald-950/20',
          badgeBg: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
          barColor: 'bg-emerald-500',
          icon: <ShieldCheck className="w-8 h-8 text-emerald-400" />,
          titleColor: 'text-emerald-400',
        };
    }
  };

  const style = getVerdictStyle();

  const getSourceBadge = () => {
    switch (result.source) {
      case 'database':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-950 text-red-300 border border-red-800">
            <Database className="w-3 h-3 mr-1" />
            Threat Database Match (Score 100)
          </span>
        );
      case 'rules':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-950 text-amber-300 border border-amber-800">
            <Wrench className="w-3 h-3 mr-1" />
            Heuristic Rule Engine
          </span>
        );
      case 'ml':
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-cyan-950 text-cyan-300 border border-cyan-800">
            <Cpu className="w-3 h-3 mr-1" />
            Lexical ML Model
          </span>
        );
      case 'combined':
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-950 text-indigo-300 border border-indigo-800">
            <Sparkles className="w-3 h-3 mr-1" />
            Combined Engine (Rules + ML)
          </span>
        );
    }
  };

  const copyJsonOutput = () => {
    const jsonOutput = {
      verdict: result.verdict,
      score: result.score,
      reasons: result.reasons,
      source: result.source,
    };
    navigator.clipboard.writeText(JSON.stringify(jsonOutput, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`rounded-2xl border ${style.border} ${style.bg} p-6 shadow-xl transition-all`}>
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800/80">
        <div className="flex items-start space-x-4">
          <div className="p-2.5 rounded-xl bg-slate-900 border border-slate-800 shadow-inner">
            {style.icon}
          </div>
          <div>
            <div className="flex items-center space-x-3 flex-wrap gap-y-1">
              <span className={`text-2xl font-extrabold tracking-tight ${style.titleColor}`}>
                {result.verdict.toUpperCase()}
              </span>
              <span className={`px-2.5 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider border ${style.badgeBg}`}>
                Risk Score: {result.score} / 100
              </span>
              {getSourceBadge()}
            </div>
            <p className="text-sm text-slate-300 mt-1 break-all">
              <span className="text-slate-500 font-medium">Target:</span>{' '}
              <span className="font-mono text-slate-200">{inputTarget}</span>
            </p>
          </div>
        </div>

        {/* Copy API Verdict JSON Button */}
        <button
          onClick={copyJsonOutput}
          className="self-start sm:self-center flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800/90 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700/80 transition"
          title="Copy JSON verdict as returned by PhishGuard API"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          <span>{copied ? 'Copied JSON!' : 'Copy Verdict JSON'}</span>
        </button>
      </div>

      {/* Risk Score Progress Meter */}
      <div className="mt-5">
        <div className="flex justify-between items-center text-xs text-slate-400 mb-1.5">
          <span className="font-medium">Threat Risk Meter</span>
          <span className="font-mono font-semibold text-slate-200">
            {result.score}% probability of malicious intent
          </span>
        </div>
        <div className="w-full bg-slate-800/80 rounded-full h-3 overflow-hidden p-0.5">
          <div
            className={`h-full rounded-full transition-all duration-700 ${style.barColor}`}
            style={{ width: `${Math.max(4, result.score)}%` }}
          />
        </div>
        <div className="flex justify-between text-[11px] text-slate-500 mt-1">
          <span>0 (Safe)</span>
          <span>30 (Threshold)</span>
          <span>70 (High Risk)</span>
          <span>100 (Confirmed Threat)</span>
        </div>
      </div>

      {/* Explainable Reasons */}
      <div className="mt-6">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2.5 flex items-center space-x-1.5">
          <Info className="w-4 h-4 text-amber-400" />
          <span>Explainability Assessment — Why this verdict was reached</span>
        </h4>
        <div className="space-y-2">
          {result.reasons.map((reason, idx) => (
            <div
              key={idx}
              className="flex items-start space-x-2.5 p-3 rounded-lg bg-slate-900/80 border border-slate-800/60 text-sm text-slate-200"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-2 flex-shrink-0" />
              <span className="leading-relaxed">{reason}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Citizen Safety Advice */}
      <div className="mt-6 p-4 rounded-xl bg-slate-900/90 border border-slate-800">
        <h4 className="text-xs font-semibold uppercase tracking-wider text-amber-400 mb-2 flex items-center space-x-1.5">
          <span>Actionable Citizen Advisory</span>
        </h4>
        <ul className="space-y-1.5 text-xs text-slate-300">
          {result.advice.map((item, idx) => (
            <li key={idx} className="flex items-start space-x-2">
              <span className="text-amber-500 font-bold">›</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>

        {result.verdict !== 'Safe' && (
          <div className="mt-3 pt-3 border-t border-slate-800 flex items-center justify-between text-xs">
            <span className="text-slate-400">Suspect fraud? Report immediately to Indian authorities:</span>
            <div className="flex items-center space-x-2 text-red-400 font-semibold">
              <PhoneCall className="w-3.5 h-3.5" />
              <span>Dial 1930 / cybercrime.gov.in</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
