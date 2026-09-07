import React, { useState } from 'react';
import { AuditResult } from '../types';
import { generateEnvExampleText, generateMarkdownReportText } from '../utils/clientAudit';
import { Download, Copy, Check, FileText, FileCode, Key } from 'lucide-react';

interface ExportSectionProps {
  result: AuditResult;
}

export const ExportSection: React.FC<ExportSectionProps> = ({ result }) => {
  const [copiedEnv, setCopiedEnv] = useState(false);
  const [copiedJson, setCopiedJson] = useState(false);

  const envContent = generateEnvExampleText(result.findings);
  const mdReport = generateMarkdownReportText(result);
  const jsonReport = JSON.stringify(
    {
      tool: 'CodeSanitizer',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      security_score: result.summary.score,
      badge: result.summary.badge,
      summary: result.summary,
      findings: result.findings,
      packages: result.packages,
    },
    null,
    2
  );

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopyEnv = () => {
    navigator.clipboard.writeText(envContent);
    setCopiedEnv(true);
    setTimeout(() => setCopiedEnv(false), 2000);
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(jsonReport);
    setCopiedJson(true);
    setTimeout(() => setCopiedJson(false), 2000);
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Download className="w-5 h-5 text-blue-600" />
          <h2 className="text-lg font-bold text-slate-900">
            Export & Remediation Artifacts
          </h2>
        </div>
        <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
          DevSecOps Outputs
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Markdown Download */}
        <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/60 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-slate-800 font-bold text-sm mb-1">
              <FileText className="w-4 h-4 text-slate-600" />
              <span>Markdown Audit Report</span>
            </div>
            <p className="text-xs text-slate-500 mb-4 leading-relaxed">
              Human-readable summary with executive metrics, package statuses, and remediation guide.
            </p>
          </div>
          <button
            onClick={() => downloadFile(mdReport, 'codesanitizer_report.md', 'text/markdown')}
            className="w-full py-2 px-3 rounded-lg bg-white border border-slate-300 text-slate-700 font-semibold text-xs hover:bg-slate-100 flex items-center justify-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download .md Report
          </button>
        </div>

        {/* JSON Download */}
        <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/60 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2 text-slate-800 font-bold text-sm">
                <FileCode className="w-4 h-4 text-indigo-600" />
                <span>DevSecOps JSON</span>
              </div>
              <button
                onClick={handleCopyJson}
                className="text-xs text-slate-500 hover:text-slate-800 flex items-center gap-1"
                title="Copy JSON"
              >
                {copiedJson ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
            <p className="text-xs text-slate-500 mb-4 leading-relaxed">
              Machine-readable structured artifact designed for CI/CD pipeline quality gates.
            </p>
          </div>
          <button
            onClick={() => downloadFile(jsonReport, 'codesanitizer_audit.json', 'application/json')}
            className="w-full py-2 px-3 rounded-lg bg-white border border-slate-300 text-slate-700 font-semibold text-xs hover:bg-slate-100 flex items-center justify-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Download .json Report
          </button>
        </div>

        {/* .env.example Download */}
        <div className="p-4 rounded-xl border border-amber-200 bg-amber-50/40 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2 text-amber-900 font-bold text-sm">
                <Key className="w-4 h-4 text-amber-600" />
                <span>Sanitized .env.example</span>
              </div>
              <button
                onClick={handleCopyEnv}
                className="text-xs text-amber-800 hover:text-amber-950 flex items-center gap-1 font-semibold"
                title="Copy .env template"
              >
                {copiedEnv ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-600" /> Copied
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" /> Copy
                  </>
                )}
              </button>
            </div>
            <p className="text-xs text-amber-800 mb-4 leading-relaxed">
              Auto-generated template extracting secret variables while <strong>strictly hiding raw secret values</strong>.
            </p>
          </div>
          <button
            onClick={() => downloadFile(envContent, '.env.example', 'text/plain')}
            className="w-full py-2 px-3 rounded-lg bg-amber-600 text-white font-semibold text-xs hover:bg-amber-700 flex items-center justify-center gap-1.5 transition-colors shadow-xs"
          >
            <Download className="w-3.5 h-3.5" />
            Download .env.example
          </button>
        </div>
      </div>

      {/* Preview of .env.example */}
      <div className="mt-4 pt-4 border-t border-slate-100">
        <details className="text-xs text-slate-600 group">
          <summary className="cursor-pointer font-bold text-slate-700 hover:text-slate-900 select-none">
            👁️ Preview Generated .env.example Template
          </summary>
          <div className="mt-2 p-3 rounded-lg bg-slate-900 text-emerald-400 font-mono text-xs overflow-x-auto border border-slate-800">
            <pre className="whitespace-pre-wrap">{envContent}</pre>
          </div>
        </details>
      </div>
    </div>
  );
};
