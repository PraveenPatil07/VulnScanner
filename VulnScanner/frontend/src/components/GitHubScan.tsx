import { useState, useCallback } from 'react';
import { Github, GitBranch, Loader2 } from 'lucide-react';
import axios from 'axios';
import { useScanStore } from '../store/scanStore';
import { useSSE } from '../hooks/useSSE';
import { scanGitHubRepo } from '../api/client';

export function GitHubScan() {
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const { reset, setStatus, setScanId } = useScanStore();
  const { connect } = useSSE();

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmed = repoUrl.trim();
    if (!trimmed) {
      setError('Please enter a GitHub repository URL');
      return;
    }

    try {
      setSubmitting(true);
      reset();
      setStatus('uploading');

      const { scan_id } = await scanGitHubRepo(trimmed, branch.trim() || 'main');
      setScanId(scan_id);
      setStatus('scanning');
      connect(scan_id);
    } catch (err: unknown) {
      let message = 'Failed to start GitHub scan';
      if (axios.isAxiosError(err)) {
        message = err.response?.data?.detail || err.message;
      } else if (err instanceof Error) {
        message = err.message;
      }
      setError(message);
      setStatus('idle');
    } finally {
      setSubmitting(false);
    }
  }, [repoUrl, branch, reset, setStatus, setScanId, connect]);

  return (
    <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-8 h-full flex flex-col justify-center hover:border-indigo-500/30 transition-all">
      <div className="flex items-center gap-2 mb-2">
        <div className="w-14 h-14 rounded-xl bg-slate-700/80 flex items-center justify-center">
          <Github className="w-7 h-7 text-slate-400" />
        </div>
      </div>
      <h3 className="text-base font-semibold text-slate-200 mt-3">Scan GitHub Repository</h3>
      <p className="text-sm text-slate-400 mt-1 mb-4">
        Enter a public repo URL or <code className="text-slate-300 bg-slate-700/50 px-1 rounded">owner/repo</code>
      </p>

      <form onSubmit={handleSubmit} className="space-y-3">
        <input
          type="text"
          value={repoUrl}
          onChange={(e) => setRepoUrl(e.target.value)}
          placeholder="https://github.com/owner/repo"
          className="w-full px-3.5 py-2.5 bg-slate-900/80 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition-all"
          disabled={submitting}
        />
        <div className="flex gap-2">
          <div className="relative flex-1">
            <GitBranch className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              placeholder="main"
              className="w-full pl-8 pr-3 py-2.5 bg-slate-900/80 border border-slate-600 rounded-lg text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500/30 transition-all"
              disabled={submitting}
            />
          </div>
          <button
            type="submit"
            disabled={submitting || !repoUrl.trim()}
            className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-600 disabled:cursor-not-allowed rounded-lg text-sm text-white font-medium transition-colors whitespace-nowrap"
          >
            {submitting ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Github className="w-4 h-4" />
            )}
            Scan
          </button>
        </div>

        {error && (
          <p className="text-xs text-red-400">{error}</p>
        )}
      </form>
    </div>
  );
}
