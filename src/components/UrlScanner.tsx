import React, { useState } from 'react';
import { Search, X, ArrowRight, Sparkles, Shield, AlertCircle } from 'lucide-react';
import { analyzeUrl } from '../engine/scoring';
import { DetectionResult } from '../types';
import { VerdictCard } from './VerdictCard';
import { TechnicalDetails } from './TechnicalDetails';

const SAMPLE_URLS = [
  {
    label: 'Fake SBI Netbanking',
    url: 'http://fake-sbi-login.com/netbanking',
    type: 'Known DB Threat',
  },
  {
    label: 'Parivahan Challan Spoof',
    url: 'http://echallan-parivahan-gov.top/pay',
    type: 'Gov Impersonation',
  },
  {
    label: 'Electricity Discom APK',
    url: 'http://192.168.1.102/bijli.apk',
    type: 'Malware APK + IP',
  },
  {
    label: 'India Post Delivery Fail',
    url: 'http://indiapost-delivery-fail.xyz/address-update',
    type: 'Postal Phish',
  },
  {
    label: 'Legitimate SBI Portal',
    url: 'https://www.onlinesbi.sbi/',
    type: 'Safe Banking',
  },
  {
    label: 'Legitimate Income Tax',
    url: 'https://incometax.gov.in/',
    type: 'Safe Sovereign',
  },
  {
    label: 'Punycode Homoglyph',
    url: 'http://xn--pypal-4ve.com/signin',
    type: 'IDN Spoof',
  },
];

export const UrlScanner: React.FC = () => {
  const [urlInput, setUrlInput] = useState('http://fake-sbi-login.com/netbanking');
  const [result, setResult] = useState<DetectionResult | null>(() =>
    analyzeUrl('http://fake-sbi-login.com/netbanking')
  );

  const handleScan = (urlToScan?: string) => {
    const target = (urlToScan ?? urlInput).trim();
    if (!target) return;
    const res = analyzeUrl(target);
    setResult(res);
  };

  const handleSelectSample = (sampleUrl: string) => {
    setUrlInput(sampleUrl);
    handleScan(sampleUrl);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleScan();
    }
  };

  return (
    <div className="space-y-6">
      {/* Intro Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-slate-850 p-6 rounded-2xl border border-slate-800 shadow-sm">
        <div className="flex items-center space-x-2 text-amber-400 text-xs font-semibold uppercase tracking-wider mb-1">
          <Shield className="w-4 h-4" />
          <span>Explainable URL Threat Inspector</span>
        </div>
        <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
          Verify any web link before clicking or entering credentials
        </h2>
        <p className="text-sm text-slate-400 mt-1 max-w-2xl">
          PhishGuard analyzes the link through our 4-tier engine: URL normalizer, threat database feeds (OpenPhish / PhishTank), Indian institutional lookalike heuristics, and lexical ML scoring.
        </p>

        {/* Input Bar */}
        <div className="mt-5 flex flex-col sm:flex-row items-stretch gap-2.5">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              <Search className="w-5 h-5" />
            </div>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Paste any URL here (e.g., https://sbi-kyc-verify.com/login.apk) …"
              className="w-full pl-11 pr-10 py-3.5 rounded-xl bg-slate-950 border border-slate-800 text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 font-mono transition"
            />
            {urlInput && (
              <button
                onClick={() => setUrlInput('')}
                className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-slate-500 hover:text-slate-300"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
          <button
            onClick={() => handleScan()}
            className="flex items-center justify-center space-x-2 px-6 py-3.5 rounded-xl bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold text-sm shadow-lg shadow-amber-500/20 transition cursor-pointer"
          >
            <span>Scan URL</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>

        {/* Quick Test Samples */}
        <div className="mt-4 pt-4 border-t border-slate-800/80">
          <div className="flex items-center space-x-1.5 text-xs text-slate-400 mb-2">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span className="font-medium">Test with Indian citizen threat scenarios:</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {SAMPLE_URLS.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => handleSelectSample(sample.url)}
                className={`text-xs px-2.5 py-1.5 rounded-lg border transition text-left flex items-center space-x-1.5 ${
                  urlInput === sample.url
                    ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                    : 'bg-slate-950/70 border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white'
                }`}
              >
                <span className="font-medium">{sample.label}</span>
                <span className="text-[10px] opacity-60 font-mono">({sample.type})</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Analysis Result */}
      {result && (
        <div className="space-y-4">
          <VerdictCard result={result} inputTarget={urlInput || result.normalized?.original || ''} />
          <TechnicalDetails result={result} />
        </div>
      )}
    </div>
  );
};
