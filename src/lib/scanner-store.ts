
"use client";

import { useState, useEffect, useCallback, useRef } from 'react';
import { Target, ReconModuleType, ReconMode } from './types';
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
    const url = settings.apiUrl.replace(/\/$/, ""); // Verwijder eventuele trailing slash
    if (!url) return;
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      
      const res = await fetch(`${url}/health`, { 
        signal: controller.signal,
        cache: 'no-store',
        mode: 'cors',
        headers: { 'Accept': 'application/json' }
      });
      
      clearTimeout(timeoutId);
      if (res.ok) {
        setIsBackendConnected(true);
      } else {
        setIsBackendConnected(false);
      }
    } catch (e) {
      // Alleen loggen als de status verandert om spam te voorkomen
      setIsBackendConnected(false);
    }
  }, [settings.apiUrl]);

  const fetchTargets = useCallback(async () => {
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!isBackendConnected || !url) return;
    try {
      const response = await fetch(`${url}/targets`, { 
        cache: 'no-store',
        mode: 'cors'
      });
      if (response.ok) {
        const data = await response.json();
        setTargets(data);
      }
    } catch (e) {
      console.error("Fetch targets failed:", e);
    }
  }, [settings.apiUrl, isBackendConnected]);

  useEffect(() => {
    checkHealth();
    const interval = setInterval(() => {
      checkHealth();
      if (isBackendConnected) {
        fetchTargets();
      }
    }, 4000);
    return () => clearInterval(interval);
  }, [checkHealth, fetchTargets, isBackendConnected]);

  const addTarget = useCallback(async (host: string, mode: ReconMode, modules: Record<ReconModuleType, boolean>) => {
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!url) return;
    try {
      const response = await fetch(`${url}/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, mode, modules }),
        mode: 'cors'
      });
      
      if (response.ok) {
        const newTarget = await response.json();
        setTargets(prev => [newTarget, ...prev]);
        setSelectedTargetId(newTarget.id);
        toast({ title: "Target Created", description: `Added ${host} to scanning pool.` });
      } else {
        throw new Error("Backend rejected target creation");
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Backend connection failed." });
    }
  }, [settings.apiUrl]);

  const deleteTarget = useCallback(async (id: string) => {
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!url) return;
    try {
      const response = await fetch(`${url}/targets/${id}`, { 
        method: 'DELETE',
        mode: 'cors'
      });
      if (response.ok) {
        setTargets(prev => prev.filter(t => t.id !== id));
        if (selectedTargetId === id) setSelectedTargetId(null);
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Could not delete target." });
    }
  }, [settings.apiUrl, selectedTargetId]);

  const pollStatus = useCallback(async (targetId: string) => {
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!url) return;
    try {
      const response = await fetch(`${url}/targets/${targetId}`, { 
        cache: 'no-store',
        mode: 'cors'
      });
      if (response.ok) {
        const updated = await response.json();
        setTargets(prev => prev.map(t => t.id === targetId ? updated : t));

        if (updated.status === 'completed') {
          if (pollingRefs.current[targetId]) {
            clearInterval(pollingRefs.current[targetId]);
            delete pollingRefs.current[targetId];
          }
          
          // Voer AI Analyse uit op ECHTE data
          if (updated.results && !updated.results.riskAnalysis) {
            try {
              const riskAnalysis = await analyzeReconDataAndProvideRiskSummary({
                target: updated.host,
                ...updated.results
              });
              
              await fetch(`${url}/targets/${targetId}/risk`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ riskAnalysis }),
                mode: 'cors'
              });
              fetchTargets();
            } catch (aiErr) {
              console.error("AI Analysis failed:", aiErr);
            }
          }
        } else if (updated.status === 'failed') {
          if (pollingRefs.current[targetId]) {
            clearInterval(pollingRefs.current[targetId]);
            delete pollingRefs.current[targetId];
          }
        }
      }
    } catch (e) {
      console.warn("Polling error:", e);
    }
  }, [settings.apiUrl, fetchTargets]);

  const runScan = useCallback(async (targetId: string) => {
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!isBackendConnected || !url) {
      toast({ variant: "destructive", title: "Scanner Offline", description: "Start the local Python service first." });
      return;
    }

    try {
      const response = await fetch(`${url}/targets/${targetId}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: settings.scanDefaults, keys: settings.apiKeys }),
        mode: 'cors'
      });

      if (response.ok) {
        if (!pollingRefs.current[targetId]) {
          pollingRefs.current[targetId] = setInterval(() => pollStatus(targetId), 2000);
        }
        fetchTargets();
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Execution Error", description: "Lost connection to backend engine." });
    }
  }, [settings.apiUrl, settings.scanDefaults, settings.apiKeys, pollStatus, isBackendConnected, fetchTargets]);

  return {
    targets,
    selectedTargetId,
    setSelectedTargetId,
    addTarget,
    deleteTarget,
    runScan,
    isBackendConnected,
    refresh: fetchTargets
  };
}
