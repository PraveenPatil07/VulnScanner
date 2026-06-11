import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';
import { useScanStore } from '../store/scanStore';
import { severityColors, severityOrder, getSeverityLabel } from '../utils/severity';
import type { Severity } from '../api/types';

export function SeverityDashboard() {
  const { result } = useScanStore();
  if (!result) return null;

  const counts: Record<Severity, number> = {
    CRITICAL: result.findings_by_severity?.CRITICAL || 0,
    HIGH: result.findings_by_severity?.HIGH || 0,
    MEDIUM: result.findings_by_severity?.MEDIUM || 0,
    LOW: result.findings_by_severity?.LOW || 0,
    INFO: result.findings_by_severity?.INFO || 0,
  };

  const pieData = severityOrder
    .filter((s) => counts[s] > 0)
    .map((s) => ({
      name: getSeverityLabel(s),
      value: counts[s],
      color: severityColors[s],
    }));

  const total = result.total_findings;

  return (
    <div className="bg-slate-800/80 rounded-xl p-5 border border-slate-700/50">
      <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide mb-4">Severity Distribution</h2>
      <div className="flex items-center gap-6">
        {/* Donut Chart */}
        <div className="w-36 h-36 shrink-0 relative">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={40}
                outerRadius={60}
                dataKey="value"
                stroke="none"
              >
                {pieData.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', fontSize: '12px' }}
                labelStyle={{ color: '#e2e8f0' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold text-white">{total}</span>
            <span className="text-[10px] text-slate-400">TOTAL</span>
          </div>
        </div>

        {/* Severity Bars */}
        <div className="flex-1 space-y-2.5">
          {severityOrder.filter(s => counts[s] > 0 || s === 'CRITICAL' || s === 'HIGH').map((s) => (
            <div key={s} className="flex items-center gap-3">
              <span className="text-xs text-slate-400 w-16">{getSeverityLabel(s)}</span>
              <div className="flex-1 bg-slate-700/50 rounded-full h-2">
                <div
                  className="h-2 rounded-full transition-all duration-500"
                  style={{
                    width: total > 0 ? `${(counts[s] / total) * 100}%` : '0%',
                    backgroundColor: severityColors[s],
                  }}
                />
              </div>
              <span className="text-sm font-semibold text-white w-8 text-right">{counts[s]}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
