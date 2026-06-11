import { useState, useEffect } from 'react';
import { History, TrendingDown, TrendingUp, Minus, ArrowLeft } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { API_BASE } from '../api/client';
import { severityColors } from '../utils/severity';

interface ScanHistoryEntry {
  scan_id: string;
  status: string;
  filename: string | null;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  scan_duration_ms: number;
  created_at: string | null;
}

interface TrendEntry {
  scan_id: string;
  filename: string | null;
  total_findings: number;
  findings_by_severity: Record<string, number>;
  created_at: string | null;
  scan_duration_ms: number;
}

interface Props {
  onBack: () => void;
  onSelectScan?: (scanId: string) => void;
}

export function ScanHistory({ onBack, onSelectScan }: Props) {
  const [history, setHistory] = useState<ScanHistoryEntry[]>([]);
  const [trends, setTrends] = useState<TrendEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch(`${API_BASE}/api/scans`).then((r) => r.json()),
      fetch(`${API_BASE}/api/trends`).then((r) => r.json()),
    ])
      .then(([histData, trendData]) => {
        setHistory(histData);
        setTrends(trendData);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const trendChartData = trends.map((t, i) => ({
    name: t.filename || `Scan ${i + 1}`,
    Critical: t.findings_by_severity?.CRITICAL || 0,
    High: t.findings_by_severity?.HIGH || 0,
    Medium: t.findings_by_severity?.MEDIUM || 0,
    Low: t.findings_by_severity?.LOW || 0,
    Total: t.total_findings,
  }));

  // Compare last two scans
  const latestDelta =
    history.length >= 2
      ? history[0].total_findings - history[1].total_findings
      : 0;

  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="animate-spin w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full mx-auto" />
        <p className="text-slate-400 mt-4">Loading scan history...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="p-2 rounded-lg bg-slate-700 hover:bg-slate-600 transition-colors"
          >
            <ArrowLeft className="w-4 h-4 text-slate-300" />
          </button>
          <div className="flex items-center gap-2">
            <History className="w-5 h-5 text-blue-400" />
            <h2 className="text-xl font-semibold text-white">Scan History</h2>
          </div>
        </div>
        {latestDelta !== 0 && (
          <div className={`flex items-center gap-1 px-3 py-1 rounded-full text-sm ${
            latestDelta > 0 ? 'bg-red-900/30 text-red-300' : 'bg-green-900/30 text-green-300'
          }`}>
            {latestDelta > 0 ? (
              <TrendingUp className="w-4 h-4" />
            ) : (
              <TrendingDown className="w-4 h-4" />
            )}
            {Math.abs(latestDelta)} findings {latestDelta > 0 ? 'more' : 'fewer'} than previous
          </div>
        )}
      </div>

      {/* Trend Chart */}
      {trendChartData.length > 1 && (
        <div className="bg-slate-800 rounded-xl border border-slate-700 p-6">
          <h3 className="text-sm font-medium text-slate-300 mb-4">Vulnerability Trend</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={trendChartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} />
              <YAxis tick={{ fill: '#94a3b8', fontSize: 12 }} />
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
              <Line type="monotone" dataKey="Critical" stroke={severityColors.CRITICAL} strokeWidth={2} dot={{ r: 4 }} />
              <Line type="monotone" dataKey="High" stroke={severityColors.HIGH} strokeWidth={2} dot={{ r: 4 }} />
              <Line type="monotone" dataKey="Medium" stroke={severityColors.MEDIUM} strokeWidth={2} dot={{ r: 4 }} />
              <Line type="monotone" dataKey="Total" stroke="#60a5fa" strokeWidth={2} strokeDasharray="5 5" dot={{ r: 3 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* History Table */}
      <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b border-slate-700">
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase">Date</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase">File</th>
              <th className="px-4 py-3 text-center text-xs font-medium text-slate-400 uppercase">Findings</th>
              <th className="px-4 py-3 text-center text-xs font-medium text-slate-400 uppercase">Critical</th>
              <th className="px-4 py-3 text-center text-xs font-medium text-slate-400 uppercase">High</th>
              <th className="px-4 py-3 text-center text-xs font-medium text-slate-400 uppercase">Duration</th>
            </tr>
          </thead>
          <tbody>
            {history.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-400">
                  No scan history available yet. Run a scan to see results here.
                </td>
              </tr>
            ) : (
              history.map((scan) => (
                <tr
                  key={scan.scan_id}
                  className="border-b border-slate-700/50 hover:bg-slate-700/50 transition-colors cursor-pointer"
                  onClick={() => onSelectScan?.(scan.scan_id)}
                >
                  <td className="px-4 py-3 text-sm text-slate-300">
                    {scan.created_at
                      ? new Date(scan.created_at).toLocaleDateString('en-US', {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                        })
                      : '—'}
                  </td>
                  <td className="px-4 py-3 text-sm text-slate-200 max-w-[200px] truncate">
                    {scan.filename || scan.scan_id.slice(0, 8)}
                  </td>
                  <td className="px-4 py-3 text-sm text-center font-medium text-white">
                    {scan.total_findings}
                  </td>
                  <td className="px-4 py-3 text-sm text-center">
                    <span className={scan.findings_by_severity?.CRITICAL ? 'text-red-400 font-bold' : 'text-slate-500'}>
                      {scan.findings_by_severity?.CRITICAL || 0}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-center">
                    <span className={scan.findings_by_severity?.HIGH ? 'text-orange-400 font-bold' : 'text-slate-500'}>
                      {scan.findings_by_severity?.HIGH || 0}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-center text-slate-400">
                    {scan.scan_duration_ms > 0
                      ? `${(scan.scan_duration_ms / 1000).toFixed(1)}s`
                      : '—'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
