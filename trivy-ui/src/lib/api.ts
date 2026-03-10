const API_BASE = 'http://localhost:8080/api/v1';

export interface Config {
  id: number;
  name: string;
  description: string;
  target_type: string;
  target_pattern: string;
  scanners: string[];
  image_config_scanners?: string[];
  severity: string[];
  ignore_unfixed: boolean;
  detection_priority: string;
  pkg_types: string[];
  pkg_relationships: string[];
  registry_auth?: any;
  ignore_file?: string;
  created_at: string;
  updated_at: string;
}

export interface Job {
  id: number;
  config_id: number;
  name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'stopped';
  target: string;
  parameters: any;
  pid: number;
  started_at: string | null;
  finished_at: string | null;
  error: { String: string; Valid: boolean };
  created_at: string;
}

export interface Result {
  id: number;
  job_id: number;
  result_type: 'vuln' | 'misconfig' | 'secret' | 'license';
  target: string;
  class: string;
  data: any;
}

export interface JobWithResults extends Job {
  results?: Result[];
}

// Configs
export async function fetchConfigs(): Promise<Config[]> {
  const res = await fetch(`${API_BASE}/configs`);
  if (!res.ok) throw new Error('Failed to fetch configs');
  return res.json();
}

export async function fetchConfig(id: number): Promise<Config> {
  const res = await fetch(`${API_BASE}/configs/${id}`);
  if (!res.ok) throw new Error('Failed to fetch config');
  return res.json();
}

export async function createConfig(config: Partial<Config>): Promise<{id: number}> {
  const res = await fetch(`${API_BASE}/configs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  });
  if (!res.ok) throw new Error('Failed to create config');
  return res.json();
}

export async function updateConfig(id: number, config: Partial<Config>): Promise<void> {
  const res = await fetch(`${API_BASE}/configs/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  });
  if (!res.ok) throw new Error('Failed to update config');
}

export async function deleteConfig(id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/configs/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete config');
}

export async function runConfig(id: number): Promise<{job_id: number}> {
  const res = await fetch(`${API_BASE}/configs/${id}/run`, { method: 'POST' });
  if (!res.ok) throw new Error('Failed to run config');
  return res.json();
}

// Jobs
export async function fetchJobs(configId?: number): Promise<Job[]> {
  let url = `${API_BASE}/jobs`;
  if (configId) url += `?config_id=${configId}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch jobs');
  return res.json();
}

export async function fetchJob(id: number): Promise<JobWithResults> {
  const res = await fetch(`${API_BASE}/jobs/${id}`);
  if (!res.ok) throw new Error('Failed to fetch job');
  return res.json();
}

export async function deleteJob(id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/jobs/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error('Failed to delete job');
}

// Quick scan (старый эндпоинт)
export async function createQuickScan(target: string): Promise<{id: number}> {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 'image', target })
  });
  if (!res.ok) throw new Error('Failed to create scan');
  return res.json();
}
