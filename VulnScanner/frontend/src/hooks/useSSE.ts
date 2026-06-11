import { useCallback, useRef } from 'react';
import { useScanStore } from '../store/scanStore';
import { createSSEConnection } from '../api/client';

export function useSSE() {
  const eventSourceRef = useRef<EventSource | null>(null);
  const { setStatus, appendReport, updateProgress, setResult, setError } = useScanStore();

  const connect = useCallback((scanId: string) => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const es = createSSEConnection(scanId);
    eventSourceRef.current = es;

    es.onmessage = (e) => {
      try {
        const event = JSON.parse(e.data);
        const type = event.type;

        if (type === 'progress') {
          const msg = event.message || event.phase || '';
          if (event.current_file) {
            console.log(`[CVScan] scanning (${event.files_scanned ?? '?'}/${event.total_files ?? '?'}): ${event.current_file}`);
          } else {
            console.log(`[CVScan] ${event.phase ?? 'progress'}: ${msg}`);
          }
          updateProgress({
            filesScanned: event.files_scanned || event.stats?.total_findings || 0,
            totalFiles: event.total_files || 0,
            currentFile: event.current_file || event.message || '',
            findingsSoFar: event.findings_so_far || 0,
          });
          if (event.phase === 'reporting') {
            setStatus('generating_report');
          } else {
            setStatus('scanning');
          }
        } else if (type === 'report_chunk') {
          setStatus('generating_report');
          appendReport(event.data || '');
        } else if (type === 'complete') {
          if (event.result) {
            setResult(event.result);
          }
          es.close();
        } else if (type === 'error') {
          setError(event.message || 'Scan failed');
          es.close();
        }
        // ignore 'keepalive'
      } catch {
        // ignore parse errors
      }
    };

    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) {
        return;
      }
      setError('SSE connection failed');
      es.close();
    };
  }, [setStatus, appendReport, updateProgress, setResult, setError]);

  const disconnect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  return { connect, disconnect };
}
