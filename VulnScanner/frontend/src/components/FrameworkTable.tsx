import { useScanStore } from '../store/scanStore';
import type { Finding } from '../api/types';

export function FrameworkTable() {
  const { result } = useScanStore();
  if (!result || !result.findings || result.findings.length === 0) return null;

  const mitreMap = new Map<string, Finding[]>();
  const nistMap = new Map<string, Finding[]>();

  result.findings.forEach((f) => {
    if (f.mitre_attack_id) {
      const t = f.mitre_attack_id;
      if (!mitreMap.has(t)) mitreMap.set(t, []);
      mitreMap.get(t)!.push(f);
    }
    (f.nist_csf ?? []).forEach((n) => {
      if (!nistMap.has(n)) nistMap.set(n, []);
      nistMap.get(n)!.push(f);
    });
  });

  if (mitreMap.size === 0 && nistMap.size === 0) return null;

  return (
    <div className="bg-slate-800/80 rounded-xl border border-slate-700/50 overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-700/50">
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wide">Framework Mapping</h2>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-slate-700/50">
        <div className="p-5">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">MITRE ATT&CK</h3>
          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {[...mitreMap.entries()].sort((a, b) => b[1].length - a[1].length).map(([tech, findings]) => (
              <div key={tech} className="flex items-center justify-between py-1 px-2 rounded hover:bg-slate-700/30">
                <span className="text-sm text-slate-300 font-mono">{tech}</span>
                <span className="text-xs font-medium text-slate-400 bg-slate-700/50 px-2 py-0.5 rounded-full">{findings.length}</span>
              </div>
            ))}
            {mitreMap.size === 0 && <p className="text-xs text-slate-500">No MITRE mappings</p>}
          </div>
        </div>

        <div className="p-5">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">NIST CSF</h3>
          <div className="space-y-1.5 max-h-48 overflow-y-auto">
            {[...nistMap.entries()].sort((a, b) => b[1].length - a[1].length).map(([fn, findings]) => (
              <div key={fn} className="flex items-center justify-between py-1 px-2 rounded hover:bg-slate-700/30">
                <span className="text-sm text-slate-300">{fn}</span>
                <span className="text-xs font-medium text-slate-400 bg-slate-700/50 px-2 py-0.5 rounded-full">{findings.length}</span>
              </div>
            ))}
            {nistMap.size === 0 && <p className="text-xs text-slate-500">No NIST mappings</p>}
          </div>
        </div>
      </div>
    </div>
  );
}
