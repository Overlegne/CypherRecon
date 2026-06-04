import { AnalyzeReconDataAndProvideRiskSummaryOutput } from '@/ai/flows/analyze-recon-data-and-provide-risk-summary';

export type ScanStatus = 'idle' | 'pending' | 'running' | 'completed' | 'failed';

export type ReconMode = 'blackbox' | 'greybox';

export type CredentialType = 
  | 'api_key' 
  | 'bearer_token' 
  | 'jwt' 
  | 'cookie' 
  | 'username_password' 
  | 'basic_auth' 
  | 'custom_header' 
  | 'query_param';

export interface Credential {
  id: string;
  type: CredentialType;
  label: string;
  value: string;
  headerName?: string;
  username?: string;
  password?: string;
  notes?: string;
  enabled: boolean;
}

export type ReconModuleType = 
  | 'subdomain_enumeration' 
  | 'osint' 
  | 'cert_transparency' 
  | 'port_scanning' 
  | 'tech_stack' 
  | 'api_discovery' 
  | 'screenshotting';

export interface OsintFinding {
  label: string;
  description: string;
  url?: string;
  type: 'leak' | 'info' | 'social' | 'code';
}

export interface Target {
  id: string;
  host: string;
  mode: ReconMode;
  status: ScanStatus;
  progress: number;
  activeModule?: ReconModuleType;
  createdAt: number;
  lastRunAt?: number;
  modules: Record<ReconModuleType, boolean>;
  credentials?: Credential[];
  results?: ScanResults;
}

export interface LogEntry {
  id: string;
  timestamp: number;
  message: string;
  type: 'info' | 'warn' | 'error' | 'success';
}

export interface ScanResults {
  logs: LogEntry[];
  subdomains?: string[];
  osintData?: OsintFinding[];
  portScanResults?: { port: number; service: string; version?: string; state: string }[];
  techStack?: string[];
  apiEndpoints?: string[];
  screenshots?: string[];
  riskAnalysis?: AnalyzeReconDataAndProvideRiskSummaryOutput;
}

export interface AppSettings {
  apiUrl: string;
  apiKeys: {
    shodan?: string;
    virustotal?: string;
    censys?: string;
    hunterio?: string;
    securitytrails?: string;
  };
  scanDefaults: {
    intensity: 'T1' | 'T2' | 'T3' | 'T4' | 'T5';
    threads: number;
    followRedirects: boolean;
    userAgent: string;
  };
}
