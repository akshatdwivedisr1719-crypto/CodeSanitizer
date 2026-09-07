import React from 'react';
import { Shield, ShieldAlert, Cpu, Terminal, FileCode, CheckCircle2 } from 'lucide-react';

export const Header: React.FC = () => {
  return (
    <header className="border-b border-slate-200 bg-white shadow-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-5">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-start gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-slate-900 text-emerald-400 flex items-center justify-center shadow-md shrink-0 border border-slate-700">
              <Shield className="w-7 h-7" />
            </div>
            <div>
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-2xl font-black tracking-tight text-slate-900">
                  CodeSanitizer
                </h1>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                  Hackathon Ready MVP
                </span>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 border border-slate-200">
                  v1.0.0
                </span>
              </div>
              <p className="text-sm font-medium text-slate-700 mt-0.5">
                AI-Generated Code & Package Hallucination Auditor
              </p>
              <p className="text-xs text-slate-500 italic mt-0.5">
                "Detect insecure AI-generated code before it reaches production."
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap text-xs text-slate-600">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 font-medium">
              <Cpu className="w-3.5 h-3.5 text-blue-600" />
              <span>Python 3.10+ AST</span>
            </div>
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 font-medium">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
              <span>Live PyPI API</span>
            </div>
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-200 font-medium">
              <Terminal className="w-3.5 h-3.5 text-amber-600" />
              <span>Streamlit UI</span>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
};
