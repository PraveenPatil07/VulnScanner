import { X, ExternalLink, Shield, AlertTriangle, Info } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import type { Finding } from '../api/types';
import { severityBgColors, getSeverityLabel } from '../utils/severity';

interface Props {
  finding: Finding;
  onClose: () => void;
}

export function FindingDetailModal({ finding, onClose }: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-slate-800 rounded-xl border border-slate-600 max-w-4xl w-full max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="sticky top-0 bg-slate-800 border-b border-slate-700 p-4 flex items-start justify-between z-10">
          <div className="flex items-start gap-3">
            <span className={`px-2 py-0.5 rounded text-xs font-bold text-white ${severityBgColors[finding.severity]}`}>
              {getSeverityLabel(finding.severity)}
            </span>
            <div>
              <h2 className="text-lg font-semibold text-white">{finding.title}</h2>
              <p className="text-sm text-slate-400 mt-0.5">
                {finding.file_path}:{finding.line_number}
              </p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-slate-700 rounded-lg transition-colors">
            <X className="w-5 h-5 text-slate-400" />
          </button>
        </div>

        <div className="p-6 space-y-6">
          {/* Description */}
          <div>
            <h3 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" /> Description
            </h3>
            <p className="text-slate-300">{finding.description}</p>
          </div>

          {/* Code Snippet */}
          {finding.code_snippet && (
            <div>
              <h3 className="text-sm font-medium text-slate-300 mb-2">Vulnerable Code</h3>
              <div className="rounded-lg overflow-hidden border border-slate-700">
                <SyntaxHighlighter
                  language={finding.language || 'python'}
                  style={vscDarkPlus}
                  customStyle={{ margin: 0, borderRadius: '0.5rem' }}
                  showLineNumbers
                  startingLineNumber={Math.max(1, finding.line_number - 3)}
                  wrapLines
                  lineProps={(lineNumber) => {
                    if (lineNumber === finding.line_number) {
                      return { style: { backgroundColor: 'rgba(239, 68, 68, 0.15)', display: 'block' } };
                    }
                    return {};
                  }}
                >
                  {finding.code_snippet}
                </SyntaxHighlighter>
              </div>
            </div>
          )}

          {/* Metadata Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <MetaItem label="CWE" value={finding.cwe_id} />
            <MetaItem label="CVSS" value={`${finding.cvss_score} / 10`} />
            <MetaItem label="Category" value={finding.category.replace(/_/g, ' ')} />
            <MetaItem label="Confidence" value={finding.confidence} />
            <MetaItem label="Language" value={finding.language} />
            <MetaItem label="MITRE ATT&CK" value={finding.mitre_attack_id || 'N/A'} />
            <MetaItem label="OWASP" value={finding.owasp_top10 || 'N/A'} />
            <MetaItem label="False Positive Risk" value={finding.false_positive_risk || 'N/A'} />
          </div>

          {/* CVSS Vector */}
          {finding.cvss_vector && (
            <div>
              <h3 className="text-sm font-medium text-slate-300 mb-1">CVSS Vector</h3>
              <code className="text-xs bg-slate-900 px-3 py-1.5 rounded text-slate-400 font-mono">
                {finding.cvss_vector}
              </code>
            </div>
          )}

          {/* NIST CSF */}
          {finding.nist_csf && finding.nist_csf.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-slate-300 mb-2">NIST CSF Controls</h3>
              <div className="flex flex-wrap gap-2">
                {finding.nist_csf.map((ctrl, i) => (
                  <span key={i} className="px-2 py-1 bg-slate-700 rounded text-xs text-slate-300">
                    {ctrl}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Remediation */}
          <div className="bg-green-900/20 border border-green-800/50 rounded-lg p-4">
            <h3 className="text-sm font-medium text-green-300 mb-2 flex items-center gap-2">
              <Shield className="w-4 h-4" /> Remediation
            </h3>
            <p className="text-green-200/80 text-sm">{finding.remediation}</p>
          </div>

          {/* References */}
          {finding.references && finding.references.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-slate-300 mb-2 flex items-center gap-2">
                <Info className="w-4 h-4" /> References
              </h3>
              <ul className="space-y-1">
                {finding.references.map((ref, i) => (
                  <li key={i}>
                    <a
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-indigo-400 hover:text-indigo-300 inline-flex items-center gap-1"
                    >
                      <ExternalLink className="w-3 h-3" />
                      {ref.replace(/^https?:\/\//, '').split('/').slice(0, 3).join('/')}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function MetaItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-slate-900/50 rounded-lg p-3">
      <p className="text-xs text-slate-500 uppercase tracking-wider">{label}</p>
      <p className="text-sm text-slate-200 mt-0.5 font-medium">{value}</p>
    </div>
  );
}
