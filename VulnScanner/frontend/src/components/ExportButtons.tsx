import { Download, FileJson, FileText } from 'lucide-react';
import { useScanStore } from '../store/scanStore';
import { useScan } from '../hooks/useScan';
import { API_BASE } from '../api/client';

export function ExportButtons() {
  const { scanId, result, reportMarkdown } = useScanStore();
  const { exportSarif } = useScan();

  if (!result || !scanId) return null;

  const downloadJSON = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-${scanId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadMarkdown = () => {
    if (!reportMarkdown) return;
    const blob = new Blob([reportMarkdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scan-${scanId}-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadPDF = () => {
    // Open PDF endpoint in new tab (triggers download)
    window.open(`${API_BASE}/api/scan/${scanId}/pdf`, '_blank');
  };

  return (
    <div className="flex flex-wrap gap-2">
      <button
        onClick={downloadJSON}
        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700/50 rounded-lg text-xs font-medium text-slate-300 transition-colors"
      >
        <Download className="w-3.5 h-3.5" /> JSON
      </button>
      <button
        onClick={() => exportSarif(scanId)}
        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700/50 rounded-lg text-xs font-medium text-slate-300 transition-colors"
      >
        <FileJson className="w-3.5 h-3.5" /> SARIF
      </button>
      <button
        onClick={downloadPDF}
        className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 rounded-lg text-xs font-medium text-white transition-colors shadow-sm"
      >
        <FileText className="w-3.5 h-3.5" /> PDF
      </button>
      {reportMarkdown && (
        <button
          onClick={downloadMarkdown}
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 border border-slate-700/50 rounded-lg text-xs font-medium text-slate-300 transition-colors"
        >
          <Download className="w-3.5 h-3.5" /> MD
        </button>
      )}
    </div>
  );
}
