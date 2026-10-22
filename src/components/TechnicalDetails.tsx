import React, { useState } from 'react';
import { DetectionResult } from '../types';
import { Terminal, Code, Cpu, ChevronDown, ChevronUp, Check, Copy } from 'lucide-react';

interface TechnicalDetailsProps {
  result: DetectionResult;
}

export const TechnicalDetails: React.FC<TechnicalDetailsProps> = ({ result }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const rawJson = {
    verdict: result.verdict,
    score: result.score,
    reasons: result.reasons,
    source: result.source,
  };

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(rawJson, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const norm = result.normalized;
  const lexical = result.lexicalFeatures;

  return (
    <div className="mt-4 rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-5 py-3.5 flex items-center justify-between text-left hover:bg-slate-850 transition"
      >
        <div className="flex items-center space-x-2">
          <Terminal className="w-4 h-4 text-amber-400" />
          <span className="text-sm font-semibold text-slate-200">
            Technical Analysis & Inspection Drawer
          </span>
          <span className="text-xs text-slate-400">
            ({result.ruleHits.length} rules evaluated, {norm ? 'Normalized URL' : 'SMS Heuristics'})
          </span>
        </div>
        <div className="flex items-center space-x-2 text-xs text-slate-400">
          <span>{isOpen ? 'Collapse' : 'Expand Details'}</span>
          {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </button>

      {isOpen && (
        <div className="p-5 border-t border-slate-800 space-y-6">
          {/* Normalization Specs */}
          {norm && (
            <div>
              <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2.5">
                URL Normalization Layer (app/normalize.py)
              </h5>
              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">Canonical URL</span>
                  <span className="font-mono text-slate-200 break-all">{norm.normalised}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">Registered Domain</span>
                  <span className="font-mono text-amber-300 font-semibold">{norm.registeredDomain}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">Host / Subdomain</span>
                  <span className="font-mono text-slate-300">
                    {norm.subdomain ? `${norm.subdomain}.` : ''}
                    {norm.host}
                  </span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">Scheme</span>
                  <span className="font-mono text-slate-300">{norm.scheme}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">TLD / Suffix</span>
                  <span className="font-mono text-slate-300">.{norm.suffix || 'none'}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block mb-1">Host Type</span>
                  <span className="font-mono text-slate-300">
                    {norm.isIp ? 'Raw Numerical IP' : 'FQDN Domain'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Lexical ML Features & Shannon Entropy */}
          {lexical && (
            <div>
              <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2.5 flex items-center space-x-1.5">
                <Cpu className="w-3.5 h-3.5 text-cyan-400" />
                <span>Lexical Features & Shannon Entropy (app/model.py)</span>
              </h5>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Domain Entropy</span>
                  <span className="font-mono text-slate-200 font-semibold text-sm">
                    {lexical.domainEntropy} bits
                  </span>
                  <span className="text-[10px] text-slate-500">
                    {lexical.domainEntropy > 3.8 ? 'High (Randomized)' : 'Normal'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Host Entropy</span>
                  <span className="font-mono text-slate-200 font-semibold text-sm">
                    {lexical.hostEntropy} bits
                  </span>
                  <span className="text-[10px] text-slate-500">Character distribution</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">Host Digit Ratio</span>
                  <span className="font-mono text-slate-200 font-semibold text-sm">
                    {Math.round(lexical.digitRatio * 100)}%
                  </span>
                  <span className="text-[10px] text-slate-500">{lexical.digitCount} digits</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                  <span className="text-slate-500 block">ML Risk Probability</span>
                  <span className="font-mono text-slate-200 font-semibold text-sm">
                    {(lexical.lexicalRiskProbability * 100).toFixed(1)}%
                  </span>
                  <span className="text-[10px] text-slate-500">Random Forest lexical</span>
                </div>
              </div>
            </div>
          )}

          {/* Rule Hits Table */}
          {result.ruleHits.length > 0 && (
            <div>
              <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2.5">
                Triggered Heuristic Rules ({result.ruleHits.length})
              </h5>
              <div className="space-y-2">
                {result.ruleHits.map((hit) => (
                  <div
                    key={hit.id}
                    className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                  >
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-slate-200">{hit.name}</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-mono bg-slate-800 text-slate-400">
                          {hit.category}
                        </span>
                      </div>
                      <p className="text-slate-400 mt-1">{hit.explanation}</p>
                    </div>
                    <div className="flex items-center space-x-2 self-start sm:self-center flex-shrink-0">
                      <span className="font-mono font-bold text-amber-400 bg-amber-950/40 border border-amber-800/40 px-2 py-0.5 rounded">
                        +{hit.points} pts
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Raw PhishGuard API JSON */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center space-x-1.5">
                <Code className="w-3.5 h-3.5 text-emerald-400" />
                <span>Standardized PhishGuard JSON API Verdict</span>
              </h5>
              <button
                onClick={copyJson}
                className="flex items-center space-x-1 text-xs text-slate-400 hover:text-white transition"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs text-emerald-400 overflow-x-auto leading-relaxed">
              {JSON.stringify(rawJson, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};
