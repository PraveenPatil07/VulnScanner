import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Sparkles } from 'lucide-react';
import { useScanStore } from '../store/scanStore';

export function ReportViewer() {
  const { reportMarkdown, status } = useScanStore();

  if (!reportMarkdown && status !== 'generating_report') return null;

  return (
    <div className="bg-slate-800/80 rounded-xl border border-slate-700/50 overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-700/50 flex items-center gap-2">
        <Sparkles className="w-4 h-4 text-purple-400" />
        <h2 className="text-sm font-semibold text-slate-200">
          AI Security Report
        </h2>
        {status === 'generating_report' && (
          <span className="ml-auto inline-flex items-center gap-1.5 text-xs text-purple-300 bg-purple-500/10 px-2 py-0.5 rounded-full border border-purple-500/20">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse" />
            Generating...
          </span>
        )}
      </div>
      <div className="p-5 prose prose-invert prose-sm max-w-none prose-headings:text-slate-200 prose-p:text-slate-300 prose-a:text-indigo-400 prose-strong:text-slate-200 prose-code:text-indigo-300 prose-code:bg-slate-700/50 prose-code:px-1 prose-code:rounded">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>
          {reportMarkdown}
        </ReactMarkdown>
      </div>
    </div>
  );
}
