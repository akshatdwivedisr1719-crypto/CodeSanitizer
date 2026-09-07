import React, { useState } from 'react';
import { VulnerabilityFinding } from '../types';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, ChevronDown, ChevronUp, Copy, Check, ShieldAlert, Sparkles } from 'lucide-react';

interface FindingsListProps {
  findings: VulnerabilityFinding[];
}

export const FindingsList: React.FC<FindingsListProps> = ({ findings }) => {
  const [expandedId, setExpandedId] = useState<Record<number, boolean>>({
    0: true,
    1: true,
    2: true,
  });
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const toggleExpand = (idx: number) => {
    setExpandedId((prev) => ({
      ...prev,
      [idx]: !prev[idx],
    }));
  };

  const handleCopy = (text: string, idx: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(idx);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-black bg-red-100 text-red-800 border border-red-300">
            <AlertOctagon className="w-3.5 h-3.5 text-red-600" />
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-black bg-orange-100 text-orange-800 border border-orange-300">
            <AlertTriangle className="w-3.5 h-3.5 text-orange-600" />
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-300">
            <AlertCircle className="w-3.5 h-3.5 text-amber-600" />
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold bg-blue-100 text-blue-800 border border-blue-300">
            <Info className="w-3.5 h-3.5 text-blue-600" />
            LOW
          </span>
        );
    }
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs">
      <div className="flex items-center justify-between mb-5">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-red-600" />
          <h2 className="text-lg font-bold text-slate-900">
            Vulnerability Findings ({findings.length})
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              const allExpanded: Record<number, boolean> = {};
              findings.forEach((_, i) => (allExpanded[i] = true));
              setExpandedId(allExpanded);
            }}
            className="text-xs font-semibold text-slate-600 hover:text-slate-900 underline"
          >
            Expand All
          </button>
          <span className="text-slate-300">|</span>
          <button
            onClick={() => setExpandedId({})}
            className="text-xs font-semibold text-slate-600 hover:text-slate-900 underline"
          >
            Collapse All
          </button>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="text-center py-10 rounded-xl bg-emerald-50/50 border border-emerald-100">
          <div className="w-12 h-12 mx-auto rounded-full bg-emerald-100 text-emerald-600 flex items-center justify-center mb-3">
            <Sparkles className="w-6 h-6" />
          </div>
          <h3 className="text-base font-bold text-emerald-950">Clean Security Audit</h3>
          <p className="text-xs text-emerald-700 mt-1 max-w-md mx-auto">
            No dangerous functions, SQL injections, hardcoded secrets, or package hallucinations detected.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {findings.map((f, idx) => {
            const isExpanded = !!expandedId[idx];
            const isCriticalOrHigh = f.severity === 'CRITICAL' || f.severity === 'HIGH';

            return (
              <div
                key={`${f.rule_id}-${f.line}-${idx}`}
                className={`rounded-xl border transition-all ${
                  isCriticalOrHigh
                    ? 'border-red-200 bg-white shadow-xs'
                    : 'border-slate-200 bg-white'
                }`}
              >
                {/* Header Row */}
                <div
                  onClick={() => toggleExpand(idx)}
                  className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-50/80 rounded-xl transition-colors select-none"
                >
                  <div className="flex items-center gap-3 flex-wrap">
                    {getSeverityBadge(f.severity)}
                    <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                      Line {f.line}
                    </span>
                    <span className="text-sm font-bold text-slate-900">{f.title}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-slate-400 hidden sm:inline">
                      {f.rule_id}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-500" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-500" />
                    )}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-1 border-t border-slate-100 space-y-4 text-sm">
                    {/* Trigger Code Snippet */}
                    <div>
                      <div className="flex items-center justify-between text-xs font-bold text-slate-600 mb-1.5">
                        <span>Triggered AST Snippet:</span>
                        <span className="text-slate-400 font-mono">Line {f.line}</span>
                      </div>
                      <div className="p-3 rounded-lg bg-slate-900 text-emerald-400 font-mono text-xs overflow-x-auto border border-slate-800">
                        <code>{f.code_snippet}</code>
                      </div>
                    </div>

                    {/* Explanation & Danger */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200">
                        <span className="text-xs font-bold uppercase tracking-wider text-slate-700 block mb-1">
                          Explanation
                        </span>
                        <p className="text-xs text-slate-700 leading-relaxed">{f.explanation}</p>
                      </div>

                      <div className="p-3.5 rounded-lg bg-red-50/50 border border-red-100">
                        <span className="text-xs font-bold uppercase tracking-wider text-red-800 block mb-1">
                          Why It Is Dangerous
                        </span>
                        <p className="text-xs text-red-900 leading-relaxed">{f.why}</p>
                      </div>
                    </div>

                    {/* Recommended Fix */}
                    <div className="p-3.5 rounded-lg bg-emerald-50/40 border border-emerald-200">
                      <span className="text-xs font-bold uppercase tracking-wider text-emerald-900 block mb-1">
                        Recommended Fix
                      </span>
                      <p className="text-xs text-emerald-900 font-medium leading-relaxed">
                        {f.recommendation}
                      </p>
                    </div>

                    {/* Before & After Diff */}
                    {f.vulnerable_example && f.recommended_example && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1">
                        {/* Vulnerable Example */}
                        <div>
                          <div className="text-xs font-bold text-red-700 mb-1 flex items-center gap-1.5">
                            <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
                            <span>Vulnerable Pattern</span>
                          </div>
                          <div className="p-3 rounded-lg bg-red-50/70 border border-red-200 font-mono text-xs text-red-900 overflow-x-auto">
                            <pre className="whitespace-pre-wrap">{f.vulnerable_example}</pre>
                          </div>
                        </div>

                        {/* Secure Example */}
                        <div>
                          <div className="flex items-center justify-between text-xs font-bold text-emerald-700 mb-1">
                            <div className="flex items-center gap-1.5">
                              <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" />
                              <span>Secure Replacement</span>
                            </div>
                            <button
                              onClick={() => handleCopy(f.recommended_example!, idx)}
                              className="text-xs text-emerald-700 hover:text-emerald-900 flex items-center gap-1 font-semibold"
                            >
                              {copiedIndex === idx ? (
                                <>
                                  <Check className="w-3 h-3" /> Copied!
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" /> Copy Fix
                                </>
                              )}
                            </button>
                          </div>
                          <div className="p-3 rounded-lg bg-emerald-50/70 border border-emerald-200 font-mono text-xs text-emerald-900 overflow-x-auto">
                            <pre className="whitespace-pre-wrap">{f.recommended_example}</pre>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
