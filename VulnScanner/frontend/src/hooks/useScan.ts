import { useCallback } from 'react';
import { useScanStore } from '../store/scanStore';
import { uploadScan, getScanResult, getSarifExport } from '../api/client';
import { useSSE } from './useSSE';

export function useScan() {
  const { setStatus, setScanId, setResult, setError, reset } = useScanStore();
  const { connect, disconnect } = useSSE();

  const startScan = useCallback(async (file: File) => {
    try {
      reset();
      setStatus('uploading');
      const { scan_id } = await uploadScan(file);
      setScanId(scan_id);
      setStatus('scanning');
      connect(scan_id);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Upload failed';
      setError(message);
    }
  }, [reset, setStatus, setScanId, setError, connect]);

  const fetchResult = useCallback(async (scanId: string) => {
    try {
      const result = await getScanResult(scanId);
      setResult(result);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to fetch results';
      setError(message);
    }
  }, [setResult, setError]);

  const exportSarif = useCallback(async (scanId: string) => {
    try {
      const sarif = await getSarifExport(scanId);
      const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `scan-${scanId}.sarif`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Export failed';
      setError(message);
    }
  }, [setError]);

  const cancelScan = useCallback(() => {
    disconnect();
    reset();
  }, [disconnect, reset]);

  return { startScan, fetchResult, exportSarif, cancelScan };
}
