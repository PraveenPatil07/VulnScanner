import { useCallback, useState } from 'react';
import { FileUpload } from '../components/FileUpload';
import { GitHubScan } from '../components/GitHubScan';
import { ScanProgress } from '../components/ScanProgress';
import { SeverityDashboard } from '../components/SeverityDashboard';
import { FindingCard } from '../components/FindingCard';
import { FindingFilters } from '../components/FindingFilters';
import { ReportViewer } from '../components/ReportViewer';
import { ExportButtons } from '../components/ExportButtons';
import { FrameworkTable } from '../components/FrameworkTable';
import { useScanStore } from '../store/scanStore';
import { AlertCircle, Shield, Bug, FileCode2 } from 'lucide-react';
import { formatDuration } from '../utils/formatters';
import { getFileLanguage } from '../utils/languageDetect';
import type { Finding } from '../api/types';

export function HomePage() {
  const { status, result, error } = useScanStore();
  const [filteredFindings, setFilteredFindings] = useState<Finding[] | null>(null);
  const [searchText, setSearchText] = useState('');

  const isScanning = status === 'uploading' || status === 'scanning' || status === 'generating_report';
  const hasFindings = result && result.findings.length > 0;
  const showResults = (status === 'completed' || status === 'generating_report') && result;

  const handleFilteredFindings = useCallback((findings: Finding[]) => {
    setFilteredFindings(findings);
  }, []);

  const handleSearchTextChange = useCallback((text: string) => {
    setSearchText(text);
  }, []);

  const displayFindings = filteredFindings ?? result?.findings ?? [];

  return (
    <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {status === 'idle' && (
        <div className="space-y-8">
          {/* Hero Section */}
          <div className="text-center space-y-3 py-4">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-sm">
              <Shield className="w-3.5 h-3.5" />
              Static Analysis + AI-Powered Reporting
            </div>
            <h2 className="text-3xl font-bold text-white">
              Scan Your Code for Vulnerabilities
            </h2>
            <p className="text-slate-400 max-w-lg mx-auto">
              Upload a ZIP archive or scan a public GitHub repository. Get detailed security findings with CVSS scores, MITRE mappings, and AI remediation guidance.
            </p>
          </div>

          {/* Upload Options - Side by Side */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <FileUpload />
            <GitHubScan />
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-4 max-w-2xl mx-auto">
            <div className="text-center p-4 rounded-xl bg-slate-800/50 border border-slate-700/50">
              <Bug className="w-5 h-5 text-indigo-400 mx-auto mb-1" />
              <p className="text-2xl font-bold text-white">288+</p>
              <p className="text-xs text-slate-400">Security Rules</p>
            </div>
            <div className="text-center p-4 rounded-xl bg-slate-800/50 border border-slate-700/50">
              <FileCode2 className="w-5 h-5 text-emerald-400 mx-auto mb-1" />
              <p className="text-2xl font-bold text-white">15+</p>
              <p className="text-xs text-slate-400">Languages</p>
            </div>
            <div className="text-center p-4 rounded-xl bg-slate-800/50 border border-slate-700/50">
              <Shield className="w-5 h-5 text-amber-400 mx-auto mb-1" />
              <p className="text-2xl font-bold text-white">OWASP</p>
              <p className="text-xs text-slate-400">Top 10 Coverage</p>
            </div>
          </div>
        </div>
      )}

      {isScanning && !showResults && <ScanProgress />}

      {error && (
        <div className="bg-red-900/20 border border-red-800/50 rounded-xl p-4 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-300">{error}</p>
        </div>
      )}

      {showResults && (
        <div className="space-y-6">
          {/* Results Header */}
          <div className="flex items-center justify-between border-b border-slate-700/50 pb-4">
            <div>
              <h2 className="text-2xl font-bold text-white">Scan Results</h2>
              <p className="text-sm text-slate-400 mt-1">
                <span className="text-indigo-300 font-medium">{result.total_findings}</span> findings across{' '}
                <span className="text-indigo-300 font-medium">{result.files_scanned}</span> files
                {result.scan_duration_ms > 0 && (
                  <span className="text-slate-500"> • {formatDuration(result.scan_duration_ms)}</span>
                )}
              </p>
            </div>
            <ExportButtons />
          </div>

          {/* Dashboard Grid */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <div className="xl:col-span-2">
              <SeverityDashboard />
            </div>
            <div>
              <LanguageSummary findings={result.findings} />
            </div>
          </div>

          {/* Findings Section - BEFORE report */}
          <FindingFilters onFilteredFindings={handleFilteredFindings} onSearchTextChange={handleSearchTextChange} />

          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <Bug className="w-5 h-5 text-orange-400" />
                Findings
                <span className="text-sm font-normal text-slate-400">({displayFindings.length})</span>
              </h3>
            </div>
            {displayFindings.map((f) => (
              <FindingCard key={f.id || `${f.file_path}:${f.line_number}:${f.rule_id}`} finding={f} searchText={searchText} />
            ))}
            {displayFindings.length === 0 && (
              <div className="text-center py-12 bg-slate-800/30 rounded-xl border border-slate-700/50">
                <p className="text-slate-400">No findings match the current filters.</p>
              </div>
            )}
          </div>

          {/* Framework + Report AFTER findings */}
          <FrameworkTable />
          <ReportViewer />
        </div>
      )}


    </main>
  );
}

function LanguageSummary({ findings }: { findings: Finding[] }) {
  const langCounts = findings.reduce<Record<string, number>>((acc, f) => {
    const lang = getFileLanguage(f.file_path, f.language);
    acc[lang] = (acc[lang] || 0) + 1;
    return acc;
  }, {});

  const sorted = Object.entries(langCounts).sort((a, b) => b[1] - a[1]);
  const total = findings.length;

  const langColors: Record<string, string> = {
    java: 'bg-orange-500',
    python: 'bg-blue-500',
    javascript: 'bg-yellow-500',
    typescript: 'bg-blue-400',
    kotlin: 'bg-purple-500',
    go: 'bg-cyan-500',
    rust: 'bg-orange-700',
    ruby: 'bg-red-500',
    php: 'bg-indigo-500',
    c: 'bg-slate-500',
    cpp: 'bg-pink-500',
    csharp: 'bg-green-600',
    swift: 'bg-orange-400',
    properties: 'bg-teal-500',
    universal: 'bg-slate-400',
  };

  return (
    <div className="bg-slate-800/80 rounded-xl p-5 border border-slate-700/50 h-full">
      <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-4">
        Findings by Language
      </h3>
      <div className="space-y-3">
        {sorted.map(([lang, count]) => (
          <div key={lang} className="flex items-center gap-3">
            <span className={`w-2.5 h-2.5 rounded-full ${langColors[lang] || 'bg-slate-500'}`} />
            <span className="text-sm text-slate-300 capitalize flex-1">{lang}</span>
            <span className="text-sm font-medium text-white">{count}</span>
            <div className="w-16 bg-slate-700 rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full ${langColors[lang] || 'bg-slate-500'}`}
                style={{ width: `${(count / total) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
