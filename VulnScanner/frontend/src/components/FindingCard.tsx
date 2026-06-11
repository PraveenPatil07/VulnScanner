import { useState } from 'react';
import { ChevronDown, ChevronUp, ExternalLink, Maximize2 } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import type { Finding } from '../api/types';
import { severityBgColors, getSeverityLabel } from '../utils/severity';
import { getFileLanguage } from '../utils/languageDetect';
import { FindingDetailModal } from './FindingDetailModal';

interface Props {
  finding: Finding;
  searchText?: string;
}

const langDisplayNames: Record<string, string> = {
  java: 'Java',
  python: 'Python',
  javascript: 'JavaScript',
  typescript: 'TypeScript',
  kotlin: 'Kotlin',
  go: 'Go',
  rust: 'Rust',
  ruby: 'Ruby',
  php: 'PHP',
  c: 'C',
  cpp: 'C++',
  csharp: 'C#',
  swift: 'Swift',
  properties: 'Config',
  universal: 'Universal',
  xml: 'XML',
};

const langBadgeColors: Record<string, string> = {
  java: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  python: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  javascript: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
  typescript: 'bg-blue-400/15 text-blue-300 border-blue-400/30',
  kotlin: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  go: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  rust: 'bg-orange-700/15 text-orange-300 border-orange-700/30',
  ruby: 'bg-red-500/15 text-red-300 border-red-500/30',
  php: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
  c: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  cpp: 'bg-pink-500/15 text-pink-300 border-pink-500/30',
  csharp: 'bg-green-500/15 text-green-300 border-green-500/30',
  swift: 'bg-orange-400/15 text-orange-300 border-orange-400/30',
  properties: 'bg-teal-500/15 text-teal-300 border-teal-500/30',
  universal: 'bg-slate-400/15 text-slate-300 border-slate-400/30',
};

function highlightText(text: string, search: string): React.ReactNode {
  if (!search || !text) return text;
  const parts = text.split(new RegExp(`(${search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi'));
  return parts.map((part, i) =>
    part.toLowerCase() === search.toLowerCase() ? (
      <mark key={i} className="bg-yellow-500/40 text-white rounded px-0.5">{part}</mark>
    ) : (
      part
    )
  );
}

export function FindingCard({ finding, searchText = '' }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [showDetail, setShowDetail] = useState(false);

  const detectedLang = getFileLanguage(finding.file_path, finding.language);
  const langName = langDisplayNames[detectedLang] || detectedLang;
  const langColor = langBadgeColors[detectedLang] || 'bg-slate-500/15 text-slate-300 border-slate-500/30';

  return (
    <div className={`rounded-xl border overflow-hidden transition-all ${
      expanded ? 'bg-slate-800 border-slate-600 shadow-lg' : 'bg-slate-800/60 border-slate-700/50 hover:border-slate-600'
    }`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3.5 flex items-center gap-3 text-left transition-colors"
      >
        {/* Severity Badge */}
        <span className={`px-2 py-0.5 rounded text-xs font-bold text-white shrink-0 ${severityBgColors[finding.severity]}`}>
          {getSeverityLabel(finding.severity)}
        </span>

        {/* Language Badge */}
        <span className={`px-2 py-0.5 rounded text-xs font-medium border shrink-0 ${langColor}`}>
          {langName}
        </span>

        {/* Title + Path */}
        <div className="flex-1 min-w-0">
          <p className="text-sm text-slate-100 font-medium truncate">{highlightText(finding.title, searchText)}</p>
          <p className="text-xs text-slate-500 truncate mt-0.5">
            {highlightText(finding.file_path, searchText)}
            <span className="text-slate-600 mx-1">:</span>
            <span className="text-slate-400">{finding.line_number}</span>
          </p>
        </div>

        {/* CVSS Score */}
        <span className={`text-xs font-mono font-semibold px-2 py-0.5 rounded shrink-0 ${
          finding.cvss_score >= 9 ? 'bg-red-900/30 text-red-300' :
          finding.cvss_score >= 7 ? 'bg-orange-900/30 text-orange-300' :
          finding.cvss_score >= 4 ? 'bg-yellow-900/30 text-yellow-300' :
          'bg-slate-700/50 text-slate-400'
        }`}>
          {finding.cvss_score}
        </span>

        {/* Detail button */}
        <span
          role="button"
          tabIndex={0}
          onClick={(e) => { e.stopPropagation(); setShowDetail(true); }}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.stopPropagation(); setShowDetail(true); } }}
          className="p-1.5 hover:bg-slate-600 rounded-lg transition-colors shrink-0"
          title="View details"
        >
          <Maximize2 className="w-3.5 h-3.5 text-slate-400" />
        </span>

        {/* Chevron */}
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-slate-500 shrink-0" />
        ) : (
          <ChevronDown className="w-4 h-4 text-slate-500 shrink-0" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700/50 pt-3 space-y-4">
          <p className="text-sm text-slate-300 leading-relaxed">{finding.description}</p>

          {finding.code_snippet && (
            <div className="rounded-lg overflow-hidden text-sm border border-slate-700/50">
              <SyntaxHighlighter
                language={detectedLang === 'properties' ? 'ini' : detectedLang}
                style={vscDarkPlus}
                customStyle={{ margin: 0, borderRadius: '0.5rem', fontSize: '0.8rem' }}
                showLineNumbers
                startingLineNumber={finding.line_number}
              >
                {finding.code_snippet}
              </SyntaxHighlighter>
            </div>
          )}

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
            <div className="bg-slate-900/50 rounded-lg px-3 py-2">
              <span className="text-xs text-slate-500 block">CWE</span>
              <span className="text-slate-200 font-medium">{finding.cwe_id}</span>
            </div>
            <div className="bg-slate-900/50 rounded-lg px-3 py-2">
              <span className="text-xs text-slate-500 block">Category</span>
              <span className="text-slate-200 font-medium">{finding.category}</span>
            </div>
            <div className="bg-slate-900/50 rounded-lg px-3 py-2">
              <span className="text-xs text-slate-500 block">Confidence</span>
              <span className="text-slate-200 font-medium">{finding.confidence}</span>
            </div>
            <div className="bg-slate-900/50 rounded-lg px-3 py-2">
              <span className="text-xs text-slate-500 block">OWASP</span>
              <span className="text-slate-200 font-medium">{finding.owasp_top10 || '—'}</span>
            </div>
          </div>

          <div className="bg-emerald-900/10 border border-emerald-800/30 rounded-lg p-3">
            <p className="text-xs font-semibold text-emerald-400 uppercase tracking-wide mb-1">Remediation</p>
            <p className="text-sm text-slate-300">{finding.remediation}</p>
          </div>

          {finding.references.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {finding.references.map((ref, i) => (
                <a
                  key={i}
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300 bg-indigo-500/10 px-2 py-1 rounded-md transition-colors"
                >
                  <ExternalLink className="w-3 h-3" /> Reference {i + 1}
                </a>
              ))}
            </div>
          )}
        </div>
      )}

      {showDetail && (
        <FindingDetailModal finding={finding} onClose={() => setShowDetail(false)} />
      )}
    </div>
  );
}
