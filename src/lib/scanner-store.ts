"use client";

import { useState, useEffect, useCallback, useRef } from 'react';
import { Target, ReconModuleType, ReconMode, LogEntry } from './types';
import { analyzeReconDataAndProvideRiskSummary } from '@/ai/flows/analyze-recon-data-and-provide-risk-summary';
import { useSettingsStore } from './settings-store';
import { toast } from '@/hooks/use-toast';

export function useScannerStore() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState<string | null>(null);
  const { settings } = useSettingsStore();
  const pollingRefs = useRef<Record<string, NodeJS.Timeout>>({});

  // Fetch targets from real backend on mount
  const fetchTargets = useCallback(async () => {
    try {
      const response = await fetch(`${settings.apiUrl}/targets`);
      if (response.ok) {
        const data = await response.json();
        setTargets(data);
      }
    } catch (e) {
      console.error("Backend connection failed", e);
    }
  }, [settings.apiUrl]);

  useEffect(() => {
    fetchTargets();
  }, [fetchTargets]);

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
        toast({ title: "Target Created", description: `Added ${host} to scanning pool.` });
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Failed to add target to backend." });
    }
  }, [settings.apiUrl]);

  const deleteTarget = useCallback(async (id: string) => {
    try {
      await fetch(`${settings.apiUrl}/targets/${id}`, { method: 'DELETE' });
      setTargets(prev => prev.filter(t => t.id !== id));
      if (selectedTargetId === id) setSelectedTargetId(null);
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Could not delete target." });
    }
  }, [settings.apiUrl, selectedTargetId]);

  const toggleModule = useCallback(async (targetId: string, module: ReconModuleType) => {
    // Optimistic UI update
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
      fetchTargets(); // Revert on failure
    }
  }, [settings.apiUrl, fetchTargets]);

  const pollStatus = useCallback(async (targetId: string) => {
    try {
      const response = await fetch(`${settings.apiUrl}/targets/${targetId}`);
      if (response.ok) {
        const updated = await response.json();
        
        setTargets(prev => prev.map(t => t.id === targetId ? updated : t));

        if (updated.status === 'completed') {
          clearInterval(pollingRefs.current[targetId]);
          delete pollingRefs.current[targetId];
          
          // Trigger AI Analysis on real data
          if (updated.results && !updated.results.riskAnalysis) {
            const riskAnalysis = await analyzeReconDataAndProvideRiskSummary({
              target: updated.host,
              ...updated.results
            });
            
            // Send AI results back to backend to persist
            fetch(`${settings.apiUrl}/targets/${targetId}/risk`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ riskAnalysis })
            }).then(() => fetchTargets());
          }
        } else if (updated.status === 'failed') {
          clearInterval(pollingRefs.current[targetId]);
          delete pollingRefs.current[targetId];
        }
      }
    } catch (e) {
      console.error("Polling error", e);
    }
  }, [settings.apiUrl, fetchTargets]);

  const runScan = useCallback(async (targetId: string) => {
    try {
      const response = await fetch(`${settings.apiUrl}/targets/${targetId}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: settings.scanDefaults, keys: settings.apiKeys })
      });

      if (response.ok) {
        setTargets(prev => prev.map(t => t.id === targetId ? { ...t, status: 'running', progress: 0 } : t));
        
        // Start real-time status polling
        if (!pollingRefs.current[targetId]) {
          pollingRefs.current[targetId] = setInterval(() => pollStatus(targetId), 2000);
        }
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Scan Failed", description: "Could not initiate backend scan process." });
    }
  }, [settings.apiUrl, settings.scanDefaults, settings.apiKeys, pollStatus]);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      Object.values(pollingRefs.current).forEach(clearInterval);
    };
  }, []);

  return {
    targets,
    selectedTargetId,
    setSelectedTargetId,
    addTarget,
    deleteTarget,
    toggleModule,
    runScan,
    refresh: fetchTargets
  };
}
