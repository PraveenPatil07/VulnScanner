import { create } from 'zustand';
import type { ScanResult, ScanStatus, Finding } from '../api/types';

interface ScanState {
  status: ScanStatus;
  scanId: string | null;
  result: ScanResult | null;
  reportMarkdown: string;
  progress: {
    filesScanned: number;
    totalFiles: number;
    currentFile: string;
    findingsSoFar: number;
  };
  error: string | null;
  setStatus: (status: ScanStatus) => void;
  setScanId: (id: string) => void;
  setResult: (result: ScanResult) => void;
  appendReport: (chunk: string) => void;
  setReportMarkdown: (md: string) => void;
  updateProgress: (p: Partial<ScanState['progress']>) => void;
  addFinding: (finding: Finding) => void;
  setError: (error: string | null) => void;
  reset: () => void;
}

const initialState = {
  status: 'idle' as ScanStatus,
  scanId: null,
  result: null,
  reportMarkdown: '',
  progress: {
    filesScanned: 0,
    totalFiles: 0,
    currentFile: '',
    findingsSoFar: 0,
  },
  error: null,
};

export const useScanStore = create<ScanState>((set) => ({
  ...initialState,
  setStatus: (status) => set({ status }),
  setScanId: (scanId) => set({ scanId }),
  setResult: (result) => set({ result, status: 'completed', reportMarkdown: result.llm_report || '' }),
  appendReport: (chunk) => set((state) => ({ reportMarkdown: state.reportMarkdown + chunk })),
  setReportMarkdown: (reportMarkdown) => set({ reportMarkdown }),
  updateProgress: (p) => set((state) => ({ progress: { ...state.progress, ...p } })),
  addFinding: (finding) => set((state) => ({
    result: state.result
      ? { ...state.result, findings: [...state.result.findings, finding] }
      : null,
  })),
  setError: (error) => set({ error, status: error ? 'error' : 'idle' }),
  reset: () => set(initialState),
}));
