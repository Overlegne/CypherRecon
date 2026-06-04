"use client";

import { useState, useEffect, useCallback } from 'react';
import { Target, ScanStatus, ReconModuleType, ReconMode, LogEntry } from './types';
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

  const addTarget = useCallback((host: string, mode: ReconMode) => {
    const newTarget: Target = {
      id: Math.random().toString(36).substr(2, 9),
      host,
      mode,
      status: 'idle',
      progress: 0,
      createdAt: Date.now(),
      modules: { ...DEFAULT_MODULES },
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
          mockResults.subdomains = ['dev.' + target.host, 'api.' + target.host, 'vpn.' + target.host, 'staging.' + target.host];
          addLog(`Found ${mockResults.subdomains.length} subdomains.`, 'success');
        } else if (module === 'port_scanning') {
          mockResults.portScanResults = [
            { port: 80, service: 'http', state: 'open', version: 'Nginx 1.18.0' },
            { port: 443, service: 'https', state: 'open', version: 'Nginx 1.18.0' },
            { port: 8080, service: 'http-proxy', state: 'open', version: 'Apache Tomcat 9.0' },
          ];
          addLog(`Identified open ports: 80, 443, 8080.`, 'success');
        } else if (module === 'tech_stack') {
          mockResults.techStack = ['React', 'Next.js', 'Vercel', 'AWS CloudFront'];
          addLog(`Detected tech stack: ${mockResults.techStack.join(', ')}`, 'success');
        } else if (module === 'api_discovery') {
          mockResults.apiEndpoints = ['/api/v1/users', '/api/v1/login', '/v2/swagger.json'];
          addLog(`Discovered ${mockResults.apiEndpoints.length} API endpoints.`, 'success');
        } else if (module === 'osint') {
          mockResults.osintData = ['Found public GitHub repo', 'Exposed mail server info'];
          addLog(`OSINT: found potential data leaks.`, 'warn');
        }

        updateTarget(targetId, { results: { ...target.results, ...mockResults, logs: [] } }); // logs handled separately
      }

      // AI Analysis
      updateTarget(targetId, { activeModule: undefined, progress: Math.round(modulesToRun.length * step) });
      addLog("Starting AI-powered risk assessment...", 'info');
      
      const riskAnalysis = await analyzeReconDataAndProvideRiskSummary({
        target: target.host,
        ...mockResults
      });

      addLog("Risk assessment complete. Generating final report.", 'success');
      
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