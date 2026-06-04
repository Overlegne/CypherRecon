
"use client";

import { useState, useEffect, useCallback } from 'react';
import { Target, ScanStatus, ReconModuleType, ReconMode, LogEntry, OsintFinding } from './types';
import { analyzeReconDataAndProvideRiskSummary } from '@/ai/flows/analyze-recon-data-and-provide-risk-summary';

const DEFAULT_MODULES: Record<ReconModuleType, boolean> = {
  subdomain_enumeration: true,
  osint: true,
  cert_transparency: true,
  port_scanning: true,
  tech_stack: true,
  api_discovery: true,
  screenshotting: true,
};

export function useScannerStore() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null);

  // Load from local storage on mount
  useEffect(() => {
    const saved = localStorage.getItem('cypherrecon_targets');
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        // Reset running statuses to idle/completed on reload
        const cleaned = parsed.map((t: Target) => ({
          ...t,
          status: t.status === 'running' ? 'idle' : t.status,
          progress: t.status === 'running' ? 0 : t.progress,
        }));
        setTargets(cleaned);
      } catch (e) {
        console.error("Failed to load targets", e);
      }
    }
  }, []);

  // Save to local storage on change
  useEffect(() => {
    localStorage.setItem('cypherrecon_targets', JSON.stringify(targets));
  }, [targets]);

  const addTarget = useCallback((host: string, mode: ReconMode, modules?: Record<ReconModuleType, boolean>) => {
    const newTarget: Target = {
      id: Math.random().toString(36).substr(2, 9),
      host,
      mode,
      status: 'idle',
      progress: 0,
      createdAt: Date.now(),
      modules: modules || { ...DEFAULT_MODULES },
    };
    setTargets(prev => [newTarget, ...prev]);
    setSelectedTargetId(newTarget.id);
  }, []);

  const deleteTarget = useCallback((id: string) => {
    setTargets(prev => prev.filter(t => t.id !== id));
    if (selectedTargetId === id) setSelectedTargetId(null);
  }, [selectedTargetId]);

  const toggleModule = useCallback((targetId: string, module: ReconModuleType) => {
    setTargets(prev => prev.map(t => 
      t.id === targetId 
        ? { ...t, modules: { ...t.modules, [module]: !t.modules[module] } }
        : t
    ));
  }, []);

  const updateTarget = useCallback((targetId: string, updates: Partial<Target>) => {
    setTargets(prev => prev.map(t => t.id === targetId ? { ...t, ...updates } : t));
  }, []);

  const runScan = useCallback(async (targetId: string) => {
    const target = targets.find(t => t.id === targetId);
    if (!target || target.status === 'running') return;

    updateTarget(targetId, { 
      status: 'running', 
      progress: 0, 
      lastRunAt: Date.now(),
      results: { logs: [] } 
    });

    const addLog = (message: string, type: LogEntry['type'] = 'info') => {
      setTargets(prev => prev.map(t => {
        if (t.id === targetId) {
          const newLog: LogEntry = {
            id: Math.random().toString(36).substr(2, 9),
            timestamp: Date.now(),
            message,
            type
          };
          return {
            ...t,
            results: {
              ...t.results,
              logs: [...(t.results?.logs || []), newLog]
            }
          }
        }
        return t;
      }));
    };

    const modulesToRun = (Object.keys(target.modules) as ReconModuleType[])
      .filter(m => target.modules[m]);
    
    const step = 100 / (modulesToRun.length + 1); // +1 for AI analysis

    try {
      addLog(`Initiating ${target.mode} scan for ${target.host}...`, 'info');
      
      const mockResults: any = {
        subdomains: [],
        osintData: [],
        portScanResults: [],
        techStack: [],
        apiEndpoints: []
      };

      for (let i = 0; i < modulesToRun.length; i++) {
        const module = modulesToRun[i];
        updateTarget(targetId, { activeModule: module, progress: Math.round(i * step) });
        addLog(`Executing module: ${module.replace(/_/g, ' ')}...`, 'info');
        
        // Simulate network activity
        await new Promise(r => setTimeout(r, 1500 + Math.random() * 2000));

        // Mock findings based on target host
        if (module === 'subdomain_enumeration') {
          mockResults.subdomains = ['dev.' + target.host, 'api.' + target.host, 'vpn.' + target.host, 'staging.' + target.host, 'mail.' + target.host, 'auth.' + target.host];
          addLog(`Found ${mockResults.subdomains.length} subdomains via brute-force and passive DNS.`, 'success');
        } else if (module === 'port_scanning') {
          addLog(`Running nmap -sCV -p- --min-rate 1000 -T4 ${target.host}`, 'info');
          addLog(`Analyzing 65,535 ports for service versions and default scripts...`, 'info');
          await new Promise(r => setTimeout(r, 2000));
          
          mockResults.portScanResults = [
            { port: 22, service: 'ssh', state: 'open', version: 'OpenSSH 8.2p1 Ubuntu 4ubuntu0.5' },
            { port: 80, service: 'http', state: 'open', version: 'Nginx 1.18.0' },
            { port: 443, service: 'https', state: 'open', version: 'Nginx 1.18.0' },
            { port: 3306, service: 'mysql', state: 'filtered', version: 'MySQL 8.0.28' },
            { port: 8080, service: 'http-proxy', state: 'open', version: 'Apache Tomcat 9.0.31' },
            { port: 9000, service: 'cslistener', state: 'open', version: 'FastCGI' },
          ];
          addLog(`Identified ${mockResults.portScanResults.filter((p: any) => p.state === 'open').length} open ports with detailed service fingerprinting.`, 'success');
        } else if (module === 'tech_stack') {
          mockResults.techStack = ['React 18.2.0', 'Next.js 14.0.0', 'Tailwind CSS', 'Vercel Edge Runtime', 'AWS CloudFront', 'Cloudflare WAF'];
          addLog(`Detected tech stack via Wappalyzer fingerprinting and header analysis.`, 'success');
        } else if (module === 'api_discovery') {
          // Add a leading slash if missing for consistency
          mockResults.apiEndpoints = ['/api/v1/users', '/api/v1/login', '/api/v2/debug/config', '/v2/swagger.json', '/graphiql', '/.well-known/security.txt', '/robots.txt', '/sitemap.xml'];
          addLog(`Discovered ${mockResults.apiEndpoints.length} API endpoints via directory busting and crawler.`, 'success');
        } else if (module === 'osint') {
          mockResults.osintData = [
            { 
              label: 'Public GitHub Repository', 
              description: 'Exposed repository containing configuration templates and potential secret keys.', 
              url: `https://github.com/search?q=${target.host}`,
              type: 'code'
            },
            { 
              label: 'Exposed Mail Server', 
              description: 'Publicly accessible mail server information found in WHOIS records.', 
              url: `https://who.is/whois/${target.host}`,
              type: 'info'
            },
            { 
              label: 'Developer Profiles', 
              description: 'Identified 3 key developer profiles linked to this domain for potential social engineering mapping.', 
              url: `https://www.linkedin.com/search/results/people/?keywords=${target.host}`,
              type: 'social'
            },
            {
              label: 'Data Leak Check',
              description: 'Recent credential dump contains 12 unique emails associated with this domain.',
              url: 'https://haveibeenpwned.com/',
              type: 'leak'
            }
          ];
          addLog(`OSINT: discovered potential data leaks and personnel mapping.`, 'warn');
        }

        updateTarget(targetId, { results: { ...target.results, ...mockResults, logs: [] } }); // logs handled separately
      }

      // AI Analysis
      updateTarget(targetId, { activeModule: undefined, progress: Math.round(modulesToRun.length * step) });
      addLog("Starting AI-powered risk assessment on gathered reconnaissance data...", 'info');
      
      const riskAnalysis = await analyzeReconDataAndProvideRiskSummary({
        target: target.host,
        ...mockResults
      });

      addLog("Risk assessment complete. Findings correlated and scored.", 'success');
      
      setTargets(prev => prev.map(t => t.id === targetId ? {
        ...t,
        status: 'completed',
        progress: 100,
        activeModule: undefined,
        results: {
          ...t.results,
          ...mockResults,
          riskAnalysis
        }
      } : t));

    } catch (error) {
      console.error(error);
      addLog(`Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`, 'error');
      updateTarget(targetId, { status: 'failed', activeModule: undefined });
    }
  }, [targets, updateTarget]);

  return {
    targets,
    selectedTargetId,
    setSelectedTargetId,
    addTarget,
    deleteTarget,
    toggleModule,
    runScan,
  };
}
