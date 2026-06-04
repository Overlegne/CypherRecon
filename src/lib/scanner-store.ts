
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
    if (!settings?.apiUrl) return;
    const url = settings.apiUrl.replace(/\/$/, ""); 
    
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
      setIsBackendConnected(false);
    }
  }, [settings?.apiUrl]);

  const fetchTargets = useCallback(async () => {
    if (!settings?.apiUrl) return;
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
  }, [settings?.apiUrl, isBackendConnected]);

  const pollStatus = useCallback(async (targetId: string) => {
    if (!settings?.apiUrl) return;
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
          
          // Trigger AI Analysis automatically on completion
          if (updated.results && !updated.results.riskAnalysis && (updated.results.portScanResults?.length > 0 || updated.results.subdomains?.length > 0)) {
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
  }, [settings?.apiUrl, fetchTargets]);

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
    if (!settings?.apiUrl) return;
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
  }, [settings?.apiUrl]);

  const deleteTarget = useCallback(async (id: string) => {
    if (!settings?.apiUrl) return;
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
        if (pollingRefs.current[id]) {
          clearInterval(pollingRefs.current[id]);
          delete pollingRefs.current[id];
        }
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Could not delete target." });
    }
  }, [settings?.apiUrl, selectedTargetId]);

  const runScan = useCallback(async (targetId: string) => {
    if (!settings?.apiUrl) return;
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
  }, [settings?.apiUrl, settings?.scanDefaults, settings?.apiKeys, pollStatus, isBackendConnected, fetchTargets]);

  const stopScan = useCallback(async (targetId: string) => {
    if (!settings?.apiUrl) return;
    const url = settings.apiUrl.replace(/\/$/, "");
    try {
      const response = await fetch(`${url}/targets/${targetId}/stop`, {
        method: 'POST',
        mode: 'cors'
      });
      if (response.ok) {
        // We let the polling update the UI when the status changes to failed/stopped on backend
        toast({ title: "Scan Stop Requested", description: "Request sent to scanner engine." });
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Failed to stop scan." });
    }
  }, [settings?.apiUrl, fetchTargets]);

  return {
    targets,
    selectedTargetId,
    setSelectedTargetId,
    addTarget,
    deleteTarget,
    runScan,
    stopScan,
    isBackendConnected,
    refresh: fetchTargets
  };
}
