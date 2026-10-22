import React, { useState } from 'react';
import { MessageSquare, ArrowRight, Sparkles, X, Languages, ExternalLink } from 'lucide-react';
import { analyzeMessage } from '../engine/scoring';
import { DetectionResult } from '../types';
import { VerdictCard } from './VerdictCard';
import { TechnicalDetails } from './TechnicalDetails';

const SAMPLE_MESSAGES = [
  {
    label: 'SBI KYC PAN Block (English)',
    language: 'English',
    text: 'Dear Customer, your State Bank of India account has been suspended due to pending PAN KYC. Update immediately within 24 hours at http://sbi-kyc-pan-update.com/login.apk to avoid permanent debit freeze.',
  },
  {
    label: 'Electricity Power Disconnection (Hinglish)',
    language: 'Hinglish',
    text: 'Dear consumer, your electricity power will be disconnected tonight at 9:30 PM from electric office because previous month bill was not updated. Please immediately pay bill or install our quick support APK: http://192.168.1.102/bijli.apk or call electricity officer 9811223344.',
  },
  {
    label: 'Traffic Police e-Challan (English)',
    language: 'English',
    text: 'Parivahan Notice: Pending traffic challan ₹2000 detected on your vehicle. Pay fine today before court warrant issued: http://echallan-parivahan-gov.top/pay',
  },
  {
    label: 'Tamil Banking Freeze (தமிழ்)',
    language: 'Tamil',
    text: 'அவசரம்: உங்கள் SBI கணக்கு இன்று மாலை மூடப்படும். பான் அட்டை சரிபார்க்க உடனடியாக புதுப்பிக்கவும்: http://sbi-tamil-verify.click/login அல்லது கணக்கு முடக்கப்படும்.',
  },
  {
    label: 'PhonePe ₹1999 Cashback (Lure)',
    language: 'English',
    text: 'Congratulations! You have won ₹1999 Diwali cashback reward in your PhonePe account. Claim money directly in your bank account now: http://phonepe-reward-scratch.xyz/claim',
  },
  {
    label: 'Legitimate Bank Alert (Safe)',
    language: 'English',
    text: 'Dear Customer, INR 2,500.00 debited from A/C XX1234 on 22-Oct-2026 via UPI. Ref: 429510123. If not done by you, forward SMS to 9223008333 or call toll-free 18001234. SBI.',
  },
];

export const MessageScanner: React.FC = () => {
  const [messageText, setMessageText] = useState(SAMPLE_MESSAGES[0].text);
  const [result, setResult] = useState<DetectionResult | null>(() =>
    analyzeMessage(SAMPLE_MESSAGES[0].text)
  );

  const handleScan = (textToScan?: string) => {
    const text = (textToScan ?? messageText).trim();
    if (!text) return;
    const res = analyzeMessage(text);
    setResult(res);
  };

  const handleSelectSample = (sampleText: string) => {
    setMessageText(sampleText);
    handleScan(sampleText);
  };

  return (
    <div className="space-y-6">
      {/* Intro Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-slate-850 p-6 rounded-2xl border border-slate-800 shadow-sm">
        <div className="flex items-center space-x-2 text-amber-400 text-xs font-semibold uppercase tracking-wider mb-1">
          <MessageSquare className="w-4 h-4" />
          <span>Multilingual SMS & Scam Message Inspector</span>
        </div>
        <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
          Detect phishing messages, urgent KYC threats & fake notices
        </h2>
        <p className="text-sm text-slate-400 mt-1 max-w-2xl">
          Trained on real Indian cyber fraud templates in English, Hindi, Hinglish, and Tamil. Extracts embedded URLs and exposes intimidation tactics, fake discom alerts, and malicious APK lures.
        </p>

        {/* Text Input Area */}
        <div className="mt-5 space-y-3">
          <div className="relative">
            <textarea
              rows={4}
              value={messageText}
              onChange={(e) => setMessageText(e.target.value)}
              placeholder="Paste suspicious SMS, WhatsApp message, or notice here …"
              className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 text-slate-100 placeholder-slate-500 text-sm focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500 font-sans transition resize-y"
            />
            {messageText && (
              <button
                onClick={() => setMessageText('')}
                className="absolute top-3.5 right-3.5 p-1 rounded-md text-slate-500 hover:text-slate-300 hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center space-x-2 text-xs text-slate-400">
              <Languages className="w-4 h-4 text-amber-400" />
              <span>Supports: English, Hindi, Hinglish, Tamil vernacular scripts</span>
            </div>

            <button
              onClick={() => handleScan()}
              className="flex items-center justify-center space-x-2 px-6 py-3 rounded-xl bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold text-sm shadow-lg shadow-amber-500/20 transition cursor-pointer"
            >
              <span>Inspect Message</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Quick Test Samples */}
        <div className="mt-4 pt-4 border-t border-slate-800/80">
          <div className="flex items-center space-x-1.5 text-xs text-slate-400 mb-2">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span className="font-medium">Common Indian scam scenarios (click to test):</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
            {SAMPLE_MESSAGES.map((sample, idx) => (
              <button
                key={idx}
                onClick={() => handleSelectSample(sample.text)}
                className={`text-xs p-2.5 rounded-lg border text-left transition flex flex-col justify-between ${
                  messageText === sample.text
                    ? 'bg-amber-500/20 border-amber-500/40 text-amber-300'
                    : 'bg-slate-950/70 border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white'
                }`}
              >
                <span className="font-semibold">{sample.label}</span>
                <span className="text-[11px] text-slate-400 line-clamp-1 mt-1">{sample.text}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Analysis Result */}
      {result && (
        <div className="space-y-4">
          {/* Detected Context Bar */}
          {result.scamContext && (
            <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center space-x-3 flex-wrap gap-2">
                <span className="text-slate-400">Scam Category:</span>
                <span className="font-semibold text-amber-400 bg-amber-950/40 border border-amber-800/40 px-2.5 py-1 rounded-md">
                  {result.scamContext.category}
                </span>

                {result.scamContext.detectedBrand && (
                  <span className="font-semibold text-cyan-300 bg-cyan-950/40 border border-cyan-800/40 px-2.5 py-1 rounded-md">
                    Targeted Brand: {result.scamContext.detectedBrand}
                  </span>
                )}

                {result.scamContext.language && (
                  <span className="text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                    Language: {result.scamContext.language}
                  </span>
                )}
              </div>

              {result.scamContext.extractedUrls && result.scamContext.extractedUrls.length > 0 && (
                <div className="flex items-center space-x-1.5 text-xs text-slate-300">
                  <ExternalLink className="w-3.5 h-3.5 text-amber-400" />
                  <span className="text-slate-400">Embedded Link:</span>
                  <span className="font-mono text-amber-300 underline break-all">
                    {result.scamContext.extractedUrls[0]}
                  </span>
                </div>
              )}
            </div>
          )}

          <VerdictCard result={result} inputTarget={messageText.slice(0, 100) + (messageText.length > 100 ? '…' : '')} />
          <TechnicalDetails result={result} />
        </div>
      )}
    </div>
  );
};
