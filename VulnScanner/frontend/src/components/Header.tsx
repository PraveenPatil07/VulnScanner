import { Shield, History, Plus } from 'lucide-react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useScanStore } from '../store/scanStore';

export function Header() {
  const { reset, status } = useScanStore();
  const navigate = useNavigate();
  const location = useLocation();

  const handleNewScan = () => {
    reset();
    navigate('/');
  };

  return (
    <header className="sticky top-0 z-50 border-b border-slate-700/50 bg-slate-900/80 backdrop-blur-xl">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3 flex items-center gap-3">
        <div
          className="flex items-center gap-2.5 cursor-pointer group"
          onClick={() => { reset(); navigate('/'); }}
        >
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center group-hover:bg-indigo-500/20 transition-colors">
            <Shield className="w-4.5 h-4.5 text-indigo-400" />
          </div>
          <h1 className="text-lg font-bold text-white tracking-tight">
            CVS<span className="text-indigo-400">can</span>
          </h1>
        </div>

        <nav className="ml-auto flex items-center gap-2">
          <button
            onClick={() => navigate('/history')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-all ${
              location.pathname === '/history'
                ? 'bg-indigo-500/15 text-indigo-300 border border-indigo-500/30'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
            }`}
          >
            <History className="w-4 h-4" />
            History
          </button>
          {(status === 'completed' || location.pathname !== '/') && (
            <button
              onClick={handleNewScan}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-sm font-medium text-white transition-colors shadow-sm shadow-indigo-500/20"
            >
              <Plus className="w-4 h-4" />
              New Scan
            </button>
          )}
        </nav>
      </div>
    </header>
  );
}
