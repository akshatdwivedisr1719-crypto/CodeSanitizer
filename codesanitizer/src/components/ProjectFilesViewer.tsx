import React, { useState, useEffect } from 'react';
import { PROJECT_FILES_METADATA } from '../data/projectFiles';
import { ProjectFileInfo } from '../types';
import { FolderGit2, FileCode, Check, Copy, Terminal, ExternalLink } from 'lucide-react';

export const ProjectFilesViewer: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<ProjectFileInfo>(PROJECT_FILES_METADATA[0]);
  const [fileContent, setFileContent] = useState<string>('Loading file content...');
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let isMounted = true;
    setLoading(true);

    fetch(`/api/file?path=${selectedFile.path}`)
      .then((res) => {
        if (res.ok) return res.text();
        throw new Error('Failed to load from backend');
      })
      .then((text) => {
        if (isMounted) {
          setFileContent(text);
          setLoading(false);
        }
      })
      .catch(() => {
        if (isMounted) {
          // Fallback message
          setFileContent(
            `# Source file: ${selectedFile.path}\n# Available locally in repository at /${selectedFile.path} and /CodeSanitizer/${selectedFile.path}`
          );
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [selectedFile]);

  const handleCopy = () => {
    navigator.clipboard.writeText(fileContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 p-6 shadow-xs">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <FolderGit2 className="w-5 h-5 text-purple-600" />
          <h2 className="text-lg font-bold text-slate-900">
            Project Architecture & Codebase Inspector
          </h2>
        </div>
        <span className="text-xs font-semibold px-2.5 py-1 rounded-full bg-purple-50 text-purple-700 border border-purple-200">
          9 Complete Production Files
        </span>
      </div>

      <p className="text-xs text-slate-500 mb-5 leading-relaxed">
        CodeSanitizer was architected as a modular, lightweight Python DevSecOps auditing suite.
        Explore each component file below to inspect its implementation and role in the pipeline.
      </p>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* File Selection Sidebar */}
        <div className="lg:col-span-4 space-y-1.5 border-r border-slate-100 pr-0 lg:pr-4">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-400 px-2 py-1">
            Project Structure (CodeSanitizer/)
          </div>
          {PROJECT_FILES_METADATA.map((file) => {
            const isSelected = selectedFile.path === file.path;
            return (
              <button
                key={file.path}
                onClick={() => setSelectedFile(file)}
                className={`w-full text-left p-2.5 rounded-lg text-xs font-medium transition-all flex items-start gap-2.5 ${
                  isSelected
                    ? 'bg-purple-50 text-purple-900 font-bold border border-purple-200 shadow-xs'
                    : 'text-slate-700 hover:bg-slate-50 border border-transparent'
                }`}
              >
                <FileCode
                  className={`w-4 h-4 shrink-0 mt-0.5 ${
                    isSelected ? 'text-purple-600' : 'text-slate-400'
                  }`}
                />
                <div className="truncate">
                  <div className="truncate font-mono">{file.path}</div>
                  <div className="text-[11px] text-slate-500 font-normal truncate">
                    {file.title}
                  </div>
                </div>
              </button>
            );
          })}

          <div className="mt-4 p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600">
            <div className="font-bold text-slate-800 flex items-center gap-1.5 mb-1">
              <Terminal className="w-3.5 h-3.5 text-slate-700" />
              <span>Run Locally:</span>
            </div>
            <code className="block bg-slate-900 text-emerald-400 p-2 rounded text-[11px] font-mono select-all">
              streamlit run app.py
            </code>
          </div>
        </div>

        {/* File Detail & Code Viewer */}
        <div className="lg:col-span-8 flex flex-col">
          <div className="bg-slate-50 border border-slate-200 rounded-t-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold px-2 py-0.5 rounded bg-white text-slate-800 border border-slate-300">
                  {selectedFile.path}
                </span>
                <span className="text-xs font-bold text-purple-700 bg-purple-50 px-2 py-0.5 rounded-full border border-purple-200">
                  {selectedFile.role}
                </span>
              </div>
              <p className="text-xs text-slate-600 mt-1.5 leading-relaxed">
                {selectedFile.description}
              </p>
            </div>

            <button
              onClick={handleCopy}
              className="self-start sm:self-center shrink-0 py-1.5 px-3 rounded-lg bg-white border border-slate-300 text-slate-700 text-xs font-semibold hover:bg-slate-100 flex items-center gap-1.5 transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" /> Copied!
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" /> Copy Code
                </>
              )}
            </button>
          </div>

          <div className="border border-t-0 border-slate-200 rounded-b-xl bg-slate-950 p-4 max-h-[460px] overflow-y-auto">
            {loading ? (
              <div className="text-slate-400 text-xs py-8 text-center font-mono">
                Loading {selectedFile.path}...
              </div>
            ) : (
              <pre className="font-mono text-xs text-emerald-400 whitespace-pre-wrap leading-relaxed">
                <code>{fileContent}</code>
              </pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
