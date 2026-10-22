import React from 'react';
import { OFFICIAL_BRANDS } from '../data/officialBrands';
import { Shield, AlertTriangle, PhoneCall, CheckCircle2, Lock, Smartphone, ExternalLink, HelpCircle } from 'lucide-react';

export const ScamGuide: React.FC = () => {
  return (
    <div className="space-y-8">
      {/* Hero Alert */}
      <div className="bg-gradient-to-r from-red-950/40 via-slate-900 to-amber-950/40 p-6 rounded-2xl border border-red-900/40">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-red-400 text-xs font-bold uppercase tracking-wider mb-1">
              <AlertTriangle className="w-4 h-4" />
              <span>National Citizen Security Advisory</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Indian Phishing Landscape & Citizen Safety Handbook
            </h2>
            <p className="text-sm text-slate-300 mt-1 max-w-2xl">
              Understand common deception vectors targeting Indian citizens: fake banking APKs, UPI QR traps, and spoofed sovereign portals.
            </p>
          </div>

          <div className="p-4 rounded-xl bg-slate-950/80 border border-red-800/60 flex items-center space-x-4">
            <div className="w-12 h-12 rounded-xl bg-red-600/20 border border-red-500/40 flex items-center justify-center text-red-400">
              <PhoneCall className="w-6 h-6 animate-bounce" />
            </div>
            <div>
              <span className="text-xs text-slate-400 block font-medium">National Cyber Crime Helpline</span>
              <span className="text-2xl font-extrabold text-white tracking-widest font-mono">1930</span>
              <a
                href="https://cybercrime.gov.in"
                target="_blank"
                rel="noreferrer"
                className="text-[11px] text-red-400 hover:underline flex items-center space-x-1"
              >
                <span>cybercrime.gov.in</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Top Scam Tactics in India */}
      <div>
        <h3 className="text-lg font-bold text-white mb-4 flex items-center space-x-2">
          <Shield className="w-5 h-5 text-amber-400" />
          <span>Top 5 Phishing Modus Operandi in India</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-500/10 text-amber-400 flex items-center justify-center font-bold text-sm">
              1
            </div>
            <h4 className="font-bold text-white text-base">Urgent Bank KYC / PAN Block SMS</h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              SMS threatens that your SBI, HDFC, or ICICI account will be permanently blocked in 24 hours. The included link leads to a credential harvesting form stealing your user ID, password, and OTP.
            </p>
            <div className="p-2.5 rounded-lg bg-slate-950 text-[11px] text-amber-300/90 font-mono">
              Golden Rule: Banks NEVER threaten instant account closure via SMS with third-party web links.
            </div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-red-500/10 text-red-400 flex items-center justify-center font-bold text-sm">
              2
            </div>
            <h4 className="font-bold text-white text-base">Traffic e-Challan APK Link</h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              Victims receive a fake message claiming their vehicle (e.g., DL-01-XX) has an unpaid fine. Clicking downloads an APK file (e.g., <code className="text-red-400">echallan-pay.apk</code>) that installs SMS-forwarding malware.
            </p>
            <div className="p-2.5 rounded-lg bg-slate-950 text-[11px] text-red-300/90 font-mono">
              Golden Rule: Government traffic challans are ONLY hosted on echallan.parivahan.gov.in. Never install an APK!
            </div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 text-cyan-400 flex items-center justify-center font-bold text-sm">
              3
            </div>
            <h4 className="font-bold text-white text-base">Electricity Disconnection Threat</h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              Script claiming "Power will be disconnected tonight at 9:30 PM due to unpaid electricity bill." Targets fear, instructing citizens to call a fraudulent mobile number or install remote screen control apps (AnyDesk, TeamViewer).
            </p>
            <div className="p-2.5 rounded-lg bg-slate-950 text-[11px] text-cyan-300/90 font-mono">
              Golden Rule: State discoms (Mahadiscom, BESCOM, UPPCL) never send night disconnection alerts via personal mobile numbers.
            </div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-400 flex items-center justify-center font-bold text-sm">
              4
            </div>
            <h4 className="font-bold text-white text-base">UPI "Receive Money" PIN Trap</h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              Fraudsters pose as buyers on OLX or send fake scratch cards ("You won ₹1999 cashback in PhonePe/GPay"). They instruct you to scan a QR code or enter your UPI PIN to "receive" the prize.
            </p>
            <div className="p-2.5 rounded-lg bg-slate-950 text-[11px] text-emerald-300/90 font-mono">
              Golden Rule: UPI PIN is ONLY entered to DEBIT money from your account. Receiving money NEVER needs a PIN.
            </div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-purple-500/10 text-purple-400 flex items-center justify-center font-bold text-sm">
              5
            </div>
            <h4 className="font-bold text-white text-base">India Post Package Failure Lure</h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              SMS claiming your speed post parcel cannot be delivered due to incomplete address. Asks to pay a ₹5 or ₹10 re-delivery fee on domains like <code className="text-red-400">indiapost-parcel.xyz</code>, stealing card credentials.
            </p>
            <div className="p-2.5 rounded-lg bg-slate-950 text-[11px] text-purple-300/90 font-mono">
              Golden Rule: India Post tracking is strictly on indiapost.gov.in. No re-delivery fee links are sent via SMS.
            </div>
          </div>

          <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 text-indigo-400 flex items-center justify-center font-bold text-sm">
              6
            </div>
            <h4 className="font-bold text-white text-base">Emergency Action: The "Golden Hour"</h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              If money was debited fraudulently, calling <strong>1930</strong> within 2 hours enables nodal cyber cells to freeze the transaction before the scammers withdraw it across mule accounts.
            </p>
            <div className="p-2.5 rounded-lg bg-slate-950 text-[11px] text-indigo-300/90 font-mono">
              Dial 1930 immediately or log in to cybercrime.gov.in to initiate freeze requests.
            </div>
          </div>
        </div>
      </div>

      {/* Directory of Verified Official Domains */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-bold text-white flex items-center space-x-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              <span>Official Verified Indian Domains Directory</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Always verify that the website URL strictly matches these registered official domains.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {OFFICIAL_BRANDS.map((brand, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col justify-between space-y-2"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span className="font-bold text-sm text-white">{brand.name}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {brand.category}
                  </span>
                </div>
                <div className="mt-2 space-y-1">
                  {brand.officialDomains.map((dom, dIdx) => (
                    <div
                      key={dIdx}
                      className="font-mono text-xs text-emerald-400 bg-emerald-950/30 border border-emerald-900/40 px-2 py-0.5 rounded flex items-center justify-between"
                    >
                      <span>https://{dom}</span>
                      <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                    </div>
                  ))}
                </div>
              </div>

              {brand.alertNote && (
                <p className="text-[11px] text-slate-400 pt-1 border-t border-slate-800/80 leading-normal">
                  {brand.alertNote}
                </p>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
