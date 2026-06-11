import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Loader2 } from 'lucide-react';
import { getScanResult } from '../api/client';
import { useScanStore } from '../store/scanStore';
import { SeverityDashboard } from '../components/SeverityDashboard';
import { FindingCard } from '../components/FindingCard';
import { FindingFilters } from '../components/FindingFilters';
import { ReportViewer } from '../components/ReportViewer';
import { ExportButtons } from '../components/ExportButtons';
import { FrameworkTable } from '../components/FrameworkTable';
import { formatDuration } from '../utils/formatters';
import type { Finding } from '../api/types';

export function ReportPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const { result, setResult, setScanId, setStatus } = useScanStore();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filteredFindings, setFilteredFindings] = useState<Finding[] | null>(null);
  const [searchText, setSearchText] = useState('');

  useEffect(() => {
    if (!scanId) return;

    // If the store already has this scan loaded, don't re-fetch
    const storeState = useScanStore.getState();
    if (storeState.scanId === scanId && storeState.result) return;

    setLoading(true);
    setError(null);
    getScanResult(scanId)
      .then((data) => {
        setScanId(scanId);
        if (data.status === 'COMPLETED') {
          setResult(data);
        } else {
          setError(`Scan is not yet complete (status: ${data.status}). Please try again shortly.`);
        }
      })
      .catch(() => {
        setError('Scan result not found or expired.');
      })
      .finally(() => setLoading(false));
  }, [scanId, setScanId, setResult]);

  const handleFilteredFindings = useCallback((findings: Finding[]) => {
    setFilteredFindings(findings);
  }, []);

  const handleSearchTextChange = useCallback((text: string) => {
    setSearchText(text);
  }, []);

  if (loading) {
    return (
      <main className="max-w-7xl mx-auto px-4 py-16 text-center">
        <Loader2 className="w-8 h-8 animate-spin text-indigo-400 mx-auto" />
        <p className="text-slate-400 mt-4">Loading scan report...</p>
      </main>
    );
  }

  if (error) {
    return (
      <main className="max-w-7xl mx-auto px-4 py-16 text-center">
        <p className="text-red-400 text-lg">{error}</p>
        <button
          onClick={() => navigate('/history')}
          className="mt-4 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-slate-200 transition-colors"
        >
          Back to History
        </button>
      </main>
    );
  }

  if (!result) {
    return (
      <main className="max-w-7xl mx-auto px-4 py-16 text-center">
        <p className="text-slate-400">No scan data loaded.</p>
        <button
          onClick={() => navigate('/')}
          className="mt-4 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-slate-200 transition-colors"
        >
          Start a New Scan
        </button>
      </main>
    );
  }

  const displayFindings = filteredFindings ?? result.findings ?? [];

  return (
    <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-slate-700/50 pb-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/history')}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700/50 transition-colors"
          >
            <ArrowLeft className="w-4 h-4 text-slate-300" />
          </button>
          <div>
            <h2 className="text-2xl font-bold text-white">Scan Results</h2>
            <p className="text-sm text-slate-400 mt-0.5">
              <span className="text-indigo-300 font-medium">{result.total_findings}</span> findings across{' '}
              <span className="text-indigo-300 font-medium">{result.files_scanned}</span> files
              {result.scan_duration_ms > 0 && (
                <span className="text-slate-500"> • {formatDuration(result.scan_duration_ms)}</span>
              )}
            </p>
          </div>
        </div>
        <ExportButtons />
      </div>

      <SeverityDashboard />

      {/* Findings Section - BEFORE framework & report */}
      <FindingFilters onFilteredFindings={handleFilteredFindings} onSearchTextChange={handleSearchTextChange} />

      <div className="space-y-3">
        <h3 className="text-lg font-semibold text-white">
          Findings <span className="text-sm font-normal text-slate-400">({displayFindings.length})</span>
        </h3>
        {displayFindings.map((f) => (
          <FindingCard key={f.id || `${f.file_path}:${f.line_number}:${f.rule_id}`} finding={f} searchText={searchText} />
        ))}
        {displayFindings.length === 0 && (
          <div className="text-center py-12 bg-slate-800/30 rounded-xl border border-slate-700/50">
            <p className="text-slate-400">No findings match the current filters.</p>
          </div>
        )}
      </div>

      <FrameworkTable />
      <ReportViewer />
    </main>
  );
}
