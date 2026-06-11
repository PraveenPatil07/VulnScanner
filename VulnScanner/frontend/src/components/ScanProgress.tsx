import { Loader2, Shield, FileSearch, Sparkles } from 'lucide-react';
import { useScanStore } from '../store/scanStore';

export function ScanProgress() {
  const { status, progress } = useScanStore();

  const percentage = progress.totalFiles > 0
    ? Math.round((progress.filesScanned / progress.totalFiles) * 100)
    : 0;

  const phases = [
    { key: 'uploading', label: 'Uploading', icon: Shield, active: status === 'uploading' },
    { key: 'scanning', label: 'Scanning', icon: FileSearch, active: status === 'scanning' },
    { key: 'generating_report', label: 'AI Report', icon: Sparkles, active: status === 'generating_report' },
  ];

  const currentPhaseIdx = phases.findIndex(p => p.active);

  return (
    <div className="bg-slate-800/80 rounded-xl p-6 border border-slate-700/50">
      {/* Phase indicators */}
      <div className="flex items-center justify-center gap-2 mb-6">
        {phases.map((phase, i) => {
          const Icon = phase.icon;
          const isComplete = i < currentPhaseIdx;
          const isCurrent = phase.active;
          return (
            <div key={phase.key} className="flex items-center gap-2">
              <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all ${
                isCurrent
                  ? 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/30'
                  : isComplete
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'text-slate-500 border border-slate-700'
              }`}>
                {isCurrent ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <Icon className="w-3 h-3" />
                )}
                {phase.label}
              </div>
              {i < phases.length - 1 && (
                <div className={`w-8 h-px ${isComplete ? 'bg-emerald-500/50' : 'bg-slate-700'}`} />
              )}
            </div>
          );
        })}
      </div>

      {/* Progress bar */}
      {status === 'scanning' && progress.totalFiles > 0 && (
        <div className="space-y-2">
          <div className="w-full bg-slate-700/50 rounded-full h-1.5">
            <div
              className="bg-gradient-to-r from-indigo-500 to-purple-500 h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${percentage}%` }}
            />
          </div>
          <div className="flex justify-between text-xs text-slate-400">
            <span>{progress.filesScanned} / {progress.totalFiles} files scanned</span>
            <span className="text-indigo-300 font-medium">{progress.findingsSoFar} findings</span>
          </div>
        </div>
      )}

      {progress.currentFile && (
        <p className="mt-3 text-xs text-slate-500 truncate text-center">
          {progress.currentFile}
        </p>
      )}
    </div>
  );
}
