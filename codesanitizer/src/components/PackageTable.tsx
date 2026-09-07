import React from 'react';
import { PackageVerificationResult } from '../types';
import { CheckCircle2, XCircle, BookOpen, AlertTriangle, ExternalLink, Package } from 'lucide-react';

interface PackageTableProps {
  packages: PackageVerificationResult[];
}

export const PackageTable: React.FC<PackageTableProps> = ({ packages }) => {
  const hallucinated = packages.filter((p) => p.status === 'NOT_FOUND');

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Package className="w-5 h-5 text-indigo-600" />
          <h2 className="text-lg font-bold text-slate-900">
            Package Security & Supply Chain Audit
          </h2>
        </div>
        <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-indigo-50 text-indigo-700 border border-indigo-200">
          Live PyPI Verification
        </span>
      </div>

      {hallucinated.length > 0 && (
        <div className="mb-5 p-4 rounded-xl bg-red-50 border border-red-200 text-red-900 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
          <div>
            <h4 className="text-sm font-bold text-red-900">
              🚨 {hallucinated.length} AI-Hallucinated Package(s) Detected!
            </h4>
            <p className="text-xs text-red-700 mt-1 leading-relaxed">
              These packages <strong>do not exist on the live PyPI registry</strong>.
              LLMs frequently hallucinate plausible package names. Attackers register these
              non-existent package names on PyPI (Dependency Squatting / Comb-squatting) to execute
              malicious code when unsuspecting developers install them.
            </p>
          </div>
        </div>
      )}

      {packages.length === 0 ? (
        <div className="text-center py-8 text-slate-500 text-sm">
          No external package imports detected in submitted code.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-700 border-collapse">
            <thead>
              <tr className="border-b border-slate-200 bg-slate-50/75 text-xs font-bold text-slate-600 uppercase tracking-wider">
                <th className="py-3 px-4">Package</th>
                <th className="py-3 px-4">Registry Status</th>
                <th className="py-3 px-4">Import Line(s)</th>
                <th className="py-3 px-4">Audit Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {packages.map((pkg) => {
                const isVerified = pkg.status === 'VERIFIED';
                const isNotFound = pkg.status === 'NOT_FOUND';
                const isStdlib = pkg.status === 'STDLIB';

                return (
                  <tr
                    key={pkg.package_name}
                    className={isNotFound ? 'bg-red-50/40 hover:bg-red-50/60' : 'hover:bg-slate-50/60'}
                  >
                    <td className="py-3 px-4 font-mono font-bold text-slate-900 flex items-center gap-2">
                      <span>{pkg.package_name}</span>
                      {pkg.homepage && (
                        <a
                          href={pkg.homepage}
                          target="_blank"
                          rel="noreferrer"
                          className="text-slate-400 hover:text-indigo-600"
                          title="Open PyPI page"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      )}
                    </td>

                    <td className="py-3 px-4">
                      {isVerified && (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          VERIFIED
                        </span>
                      )}
                      {isNotFound && (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-red-100 text-red-800 border border-red-300 animate-pulse">
                          <XCircle className="w-3.5 h-3.5 text-red-600" />
                          NOT FOUND (HALLUCINATED)
                        </span>
                      )}
                      {isStdlib && (
                        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200">
                          <BookOpen className="w-3.5 h-3.5" />
                          Python Standard Library
                        </span>
                      )}
                      {!isVerified && !isNotFound && !isStdlib && (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-700">
                          {pkg.status}
                        </span>
                      )}
                    </td>

                    <td className="py-3 px-4 font-mono text-xs text-slate-600">
                      {pkg.lines && pkg.lines.length > 0 ? (
                        pkg.lines.map((l) => (
                          <span
                            key={l}
                            className="inline-block mr-1 px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200"
                          >
                            L{l}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-400">N/A</span>
                      )}
                    </td>

                    <td className="py-3 px-4 text-xs">
                      {isVerified ? (
                        <div>
                          <span className="font-semibold text-slate-900">
                            {pkg.version ? `v${pkg.version}` : 'Active Release'}
                          </span>
                          {pkg.summary && (
                            <span className="text-slate-500 ml-1.5">
                              - {pkg.summary.length > 80 ? `${pkg.summary.slice(0, 80)}...` : pkg.summary}
                            </span>
                          )}
                        </div>
                      ) : isNotFound ? (
                        <span className="text-red-700 font-medium">
                          Does not exist on PyPI. Potential hallucination or supply-chain threat.
                        </span>
                      ) : (
                        <span className="text-slate-600">{pkg.message}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
