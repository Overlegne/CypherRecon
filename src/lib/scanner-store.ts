
"use client";

import { useState, useEffect, useCallback, useRef } from 'react';
import { Target, ReconModuleType, ReconMode, LogEntry } from './types';
import { analyzeReconDataAndProvideRiskSummary } from '@/ai/flows/analyze-recon-data-and-provide-risk-summary';
import { useSettingsStore } from './settings-store';
import { toast } from '@/hooks/use-toast';

export function useScannerStore() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);
  const { settings } = useSettingsStore();
  const pollingRefs = useRef<Record<string, NodeJS.Timeout>>({});

  const checkHealth = useCallback(async () => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      
      const res = await fetch(`${settings.apiUrl}/health`, { 
        signal: controller.signal,
        cache: 'no-store'
      });
      clearTimeout(timeoutId);
      setIsBackendConnected(res.ok);
    } catch (e) {
      setIsBackendConnected(false);
    }
  }, [settings.apiUrl]);

  const fetchTargets = useCallback(async () => {
    try {
      const response = await fetch(`${settings.apiUrl}/targets`, { cache: 'no-store' });
      if (response.ok) {
        const data = await response.json();
        setTargets(data);
      }
    } catch (e) {
      // Backend might be down, handled by checkHealth
    }
  }, [settings.apiUrl]);

  useEffect(() => {
    checkHealth();
    fetchTargets();
    const interval = setInterval(() => {
      checkHealth();
      fetchTargets();
    }, 5000);
    return () => clearInterval(interval);
  }, [checkHealth, fetchTargets]);

  const addTarget = useCallback(async (host: string, mode: ReconMode, modules: Record<ReconModuleType, boolean>) => {
    try {
      const response = await fetch(`${settings.apiUrl}/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, mode, modules })
      });
      
      if (response.ok) {
        const newTarget = await response.json();
        setTargets(prev => [newTarget, ...prev]);
        setSelectedTargetId(newTarget.id);
        toast({ title: "Target Created", description: `Added ${host} to pool.` });
      } else {
        throw new Error("Failed to create target");
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Connection Error", description: "Backend is unreachable or returned an error." });
    }
  }, [settings.apiUrl]);

  const deleteTarget = useCallback(async (id: string) => {
    try {
      const response = await fetch(`${settings.apiUrl}/targets/${id}`, { method: 'DELETE' });
      if (response.ok) {
        setTargets(prev => prev.filter(t => t.id !== id));
        if (selectedTargetId === id) setSelectedTargetId(null);
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Could not delete target." });
    }
  }, [settings.apiUrl, selectedTargetId]);

  const toggleModule = useCallback(async (targetId: string, module: ReconModuleType) => {
    setTargets(prev => prev.map(t => 
      t.id === targetId 
        ? { ...t, modules: { ...t.modules, [module]: !t.modules[module] } }
        : t
    ));

    try {
      await fetch(`${settings.apiUrl}/targets/${targetId}/modules`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ module })
      });
    } catch (e) {
      fetchTargets();
    }
  }, [settings.apiUrl, fetchTargets]);

  const pollStatus = useCallback(async (targetId: string) => {
    try {
      const response = await fetch(`${settings.apiUrl}/targets/${targetId}`, { cache: 'no-store' });
      if (response.ok) {
        const updated = await response.json();
        setTargets(prev => prev.map(t => t.id === targetId ? updated : t));

        if (updated.status === 'completed') {
          if (pollingRefs.current[targetId]) {
            clearInterval(pollingRefs.current[targetId]);
            delete pollingRefs.current[targetId];
          }
          
          if (updated.results && !updated.results.riskAnalysis) {
            const riskAnalysis = await analyzeReconDataAndProvideRiskSummary({
              target: updated.host,
              ...updated.results
            });
            
            fetch(`${settings.apiUrl}/targets/${targetId}/risk`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ riskAnalysis })
            }).then(() => fetchTargets());
          }
        } else if (updated.status === 'failed') {
          if (pollingRefs.current[targetId]) {
            clearInterval(pollingRefs.current[targetId]);
            delete pollingRefs.current[targetId];
          }
        }
      }
    } catch (e) {
      setIsBackendConnected(false);
    }
  }, [settings.apiUrl, fetchTargets]);

  const runScan = useCallback(async (targetId: string) => {
    if (!isBackendConnected) {
      toast({ variant: "destructive", title: "Backend Offline", description: "Please start your local scanner service." });
      return;
    }

    try {
      const response = await fetch(`${settings.apiUrl}/targets/${targetId}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: settings.scanDefaults, keys: settings.apiKeys })
      });

      if (response.ok) {
        setTargets(prev => prev.map(t => t.id === targetId ? { ...t, status: 'running', progress: 0 } : t));
        if (!pollingRefs.current[targetId]) {
          pollingRefs.current[targetId] = setInterval(() => pollStatus(targetId), 2000);
        }
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Scan Failed", description: "Backend connection lost during initiation." });
    }
  }, [settings.apiUrl, settings.scanDefaults, settings.apiKeys, pollStatus, isBackendConnected]);

  return {
    targets,
    selectedTargetId,
    setSelectedTargetId,
    addTarget,
    deleteTarget,
    toggleModule,
    runScan,
    isBackendConnected,
    refresh: fetchTargets
  };
}
