import React from 'react';
import { AuditSummary } from '../types';
import { AlertOctagon, AlertTriangle, AlertCircle, Info, CheckCircle2, ShieldCheck, ShieldAlert } from 'lucide-react';

interface ScoreCardProps {
  summary: AuditSummary;
}

export const ScoreCard: React.FC<ScoreCardProps> = ({ summary }) => {
  const { score, badge, counts, explanation } = summary;

  // Color logic based on score
  let scoreColor = 'text-red-600';
  let bgColor = 'bg-red-50 border-red-200';
  let progressColor = 'bg-red-500';

  if (score >= 90) {
    scoreColor = 'text-emerald-600';
    bgColor = 'bg-emerald-50 border-emerald-200';
    progressColor = 'bg-emerald-500';
  } else if (score >= 75) {
    scoreColor = 'text-amber-600';
    bgColor = 'bg-amber-50 border-amber-200';
    progressColor = 'bg-amber-500';
  } else if (score >= 50) {
    scoreColor = 'text-orange-600';
    bgColor = 'bg-orange-50 border-orange-200';
    progressColor = 'bg-orange-500';
  }

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          {score >= 75 ? (
            <ShieldCheck className="w-5 h-5 text-emerald-600" />
          ) : (
            <ShieldAlert className="w-5 h-5 text-red-600" />
          )}
          <h2 className="text-lg font-bold text-slate-900">Security Overview</h2>
        </div>
        <span className="text-xs font-semibold px-2.5 py-1 rounded-full border bg-slate-100 text-slate-700 border-slate-200">
          Deterministic 0–100 Scale
        </span>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {/* Main Score Box */}
        <div className={`col-span-2 md:col-span-1 rounded-xl p-4 border flex flex-col items-center justify-center ${bgColor}`}>
          <span className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-1">
            Security Score
          </span>
          <div className="flex items-baseline gap-1">
            <span className={`text-4xl font-black ${scoreColor}`}>{score}</span>
            <span className="text-sm font-semibold text-slate-500">/100</span>
          </div>
          <span className="text-xs font-bold mt-1 text-slate-800 text-center">
            {badge}
          </span>
          {/* Progress bar */}
          <div className="w-full bg-slate-200/80 rounded-full h-1.5 mt-3 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${progressColor}`}
              style={{ width: `${score}%` }}
            />
          </div>
        </div>

        {/* Critical Metric */}
        <div className="bg-slate-50 rounded-xl p-4 border border-slate-200 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-600">CRITICAL</span>
            <AlertOctagon className="w-4 h-4 text-red-600" />
          </div>
          <div className="mt-2">
            <span className={`text-3xl font-black ${counts.CRITICAL > 0 ? 'text-red-600' : 'text-slate-700'}`}>
              {counts.CRITICAL}
            </span>
            <p className="text-xs text-slate-500 mt-0.5">-30 pts each</p>
          </div>
        </div>

        {/* High Metric */}
        <div className="bg-slate-50 rounded-xl p-4 border border-slate-200 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-600">HIGH</span>
            <AlertTriangle className="w-4 h-4 text-orange-600" />
          </div>
          <div className="mt-2">
            <span className={`text-3xl font-black ${counts.HIGH > 0 ? 'text-orange-600' : 'text-slate-700'}`}>
              {counts.HIGH}
            </span>
            <p className="text-xs text-slate-500 mt-0.5">-15 pts each</p>
          </div>
        </div>

        {/* Medium Metric */}
        <div className="bg-slate-50 rounded-xl p-4 border border-slate-200 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-600">MEDIUM</span>
            <AlertCircle className="w-4 h-4 text-amber-500" />
          </div>
          <div className="mt-2">
            <span className={`text-3xl font-black ${counts.MEDIUM > 0 ? 'text-amber-600' : 'text-slate-700'}`}>
              {counts.MEDIUM}
            </span>
            <p className="text-xs text-slate-500 mt-0.5">-8 pts each</p>
          </div>
        </div>

        {/* Low Metric */}
        <div className="bg-slate-50 rounded-xl p-4 border border-slate-200 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-slate-600">LOW</span>
            <Info className="w-4 h-4 text-blue-500" />
          </div>
          <div className="mt-2">
            <span className={`text-3xl font-black text-slate-700`}>
              {counts.LOW}
            </span>
            <p className="text-xs text-slate-500 mt-0.5">-3 pts each</p>
          </div>
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 flex-wrap gap-2">
        <span className="font-medium text-slate-700">Scoring Formula:</span>
        <span>{explanation}</span>
      </div>
    </div>
  );
};
