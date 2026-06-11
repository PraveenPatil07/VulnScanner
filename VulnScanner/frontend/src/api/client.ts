import axios from 'axios';
import type { ScanResult, HealthResponse } from './types';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const client = axios.create({
  baseURL: API_BASE,
  timeout: 120000,
});

export async function uploadScan(file: File): Promise<{ scan_id: string }> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await client.post<{ scan_id: string }>('/api/scan', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return res.data;
}

export async function scanGitHubRepo(repoUrl: string, branch: string = 'main'): Promise<{ scan_id: string }> {
  const res = await client.post<{ scan_id: string }>('/api/scan/github', {
    repo_url: repoUrl,
    branch,
  });
  return res.data;
}

export async function getScanResult(scanId: string): Promise<ScanResult> {
  const res = await client.get<ScanResult>(`/api/scan/${scanId}/result`);
  return res.data;
}

export async function getSarifExport(scanId: string): Promise<object> {
  const res = await client.get(`/api/scan/${scanId}/sarif`);
  return res.data;
}

export async function getHealth(): Promise<HealthResponse> {
  const res = await client.get<HealthResponse>('/api/health');
  return res.data;
}

export function createSSEConnection(scanId: string): EventSource {
  return new EventSource(`${API_BASE}/api/scan/${scanId}/stream`);
}

export { API_BASE };
