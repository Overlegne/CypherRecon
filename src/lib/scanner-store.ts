
"use client";

import { useState, useEffect, useCallback, useRef } from 'react';
import { TargetGroup, ReconModuleType, ReconMode, Credential, ChildTarget } from './types';
import { analyzeReconDataAndProvideRiskSummary } from '@/ai/flows/analyze-recon-data-and-provide-risk-summary';
import { useSettingsStore } from './settings-store';
import { toast } from '@/hooks/use-toast';

export function useScannerStore() {
  const [targetGroups, setTargetGroups] = useState<TargetGroup[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
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

  const fetchGroups = useCallback(async () => {
    if (!settings?.apiUrl) return;
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!url) return;
    try {
      const response = await fetch(`${url}/targets`, { 
        cache: 'no-store',
        mode: 'cors'
      });
      if (response.ok) {
        const data = await response.json();
        setTargetGroups(data);
      }
    } catch (e) {
      console.error("Fetch groups failed:", e);
    }
  }, [settings?.apiUrl]);

  const pollStatus = useCallback(async (groupId: string) => {
    if (!settings?.apiUrl) return;
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!url) return;
    try {
      const response = await fetch(`${url}/targets/${groupId}`, { 
        cache: 'no-store',
        mode: 'cors'
      });
      if (response.ok) {
        const updatedGroup: TargetGroup = await response.json();
        setTargetGroups(prev => prev.map(g => g.id === groupId ? updatedGroup : g));

        if (updatedGroup.status === 'completed' || updatedGroup.status === 'failed') {
          if (pollingRefs.current[groupId]) {
            clearInterval(pollingRefs.current[groupId]);
            delete pollingRefs.current[groupId];
          }
          fetchGroups();
        }
      }
    } catch (e) {
      console.warn("Polling error:", e);
    }
  }, [settings?.apiUrl, fetchGroups]);

  const runAIAnalysis = async (groupId: string, childId: string) => {
    if (!settings?.apiUrl) return;
    const url = settings.apiUrl.replace(/\/$/, "");
    
    const group = targetGroups.find(g => g.id === groupId);
    const child = group?.childTargets.find(c => c.id === childId);

    if (!child || !child.results) {
      toast({ variant: "destructive", title: "Missing Data", description: "Target scan must be completed before analysis." });
      return;
    }

    setIsAnalyzing(true);
    try {
      toast({ title: "AI Analysis Started", description: `Processing reconnaissance data for ${child.host}...` });
      
      const riskAnalysis = await analyzeReconDataAndProvideRiskSummary({
        target: child.host,
        ...child.results
      });
      
      await fetch(`${url}/targets/${groupId}/risk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ childId: child.id, riskAnalysis }),
        mode: 'cors'
      });

      setTargetGroups(prev => prev.map(g => {
        if (g.id === groupId) {
          return {
            ...g,
            childTargets: g.childTargets.map(ct => 
              ct.id === childId ? { ...ct, results: { ...ct.results, riskAnalysis } } : ct
            )
          };
        }
        return g;
      }));

      toast({ title: "Analysis Complete", description: "AI Threat Assessment has been generated." });
    } catch (aiErr) {
      console.error("AI Analysis failed:", aiErr);
      toast({ variant: "destructive", title: "AI Error", description: "Failed to generate risk assessment. Check quota or connectivity." });
    } finally {
      setIsAnalyzing(false);
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(() => {
      checkHealth();
      fetchGroups();
      targetGroups.forEach(g => {
        if (g.status === 'running' && !pollingRefs.current[g.id]) {
          pollingRefs.current[g.id] = setInterval(() => pollStatus(g.id), 2000);
        }
      });
    }, 3000);
    return () => clearInterval(interval);
  }, [checkHealth, fetchGroups, targetGroups, pollStatus]);

  const addTargetGroup = useCallback(async (name: string, hosts: string[], mode: ReconMode, modules: Record<ReconModuleType, boolean>, credentials?: Credential[]) => {
    if (!settings?.apiUrl) return;
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!url) return;
    try {
      const response = await fetch(`${url}/targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, hosts, mode, modules, credentials }),
        mode: 'cors'
      });
      
      if (response.ok) {
        const newGroup = await response.json();
        setTargetGroups(prev => [newGroup, ...prev]);
        setSelectedGroupId(newGroup.id);
        toast({ title: "Target Group Created", description: `Added ${name} with ${hosts.length} targets.` });
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Backend connection failed." });
    }
  }, [settings?.apiUrl]);

  const deleteTargetGroup = useCallback(async (id: string) => {
    if (!settings?.apiUrl) return;
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!url) return;
    try {
      const response = await fetch(`${url}/targets/${id}`, { 
        method: 'DELETE',
        mode: 'cors'
      });
      if (response.ok) {
        setTargetGroups(prev => prev.filter(g => g.id !== id));
        if (selectedGroupId === id) setSelectedGroupId(null);
        if (pollingRefs.current[id]) {
          clearInterval(pollingRefs.current[id]);
          delete pollingRefs.current[id];
        }
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Could not delete target group." });
    }
  }, [settings?.apiUrl, selectedGroupId]);

  const runScan = useCallback(async (groupId: string) => {
    if (!settings?.apiUrl) return;
    const url = settings.apiUrl.replace(/\/$/, "");
    if (!isBackendConnected || !url) {
      toast({ variant: "destructive", title: "Scanner Offline", description: "Start the local Python service first." });
      return;
    }

    try {
      const response = await fetch(`${url}/targets/${groupId}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config: settings.scanDefaults, keys: settings.apiKeys }),
        mode: 'cors'
      });

      if (response.ok) {
        if (!pollingRefs.current[groupId]) {
          pollingRefs.current[groupId] = setInterval(() => pollStatus(groupId), 1000);
        }
        fetchGroups();
        toast({ title: "Scan Initiated", description: "Sequence started on backend engine." });
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Execution Error", description: "Lost connection to backend engine." });
    }
  }, [settings?.apiUrl, settings?.scanDefaults, settings?.apiKeys, pollStatus, isBackendConnected, fetchGroups]);

  const stopScan = useCallback(async (groupId: string) => {
    if (!settings?.apiUrl) return;
    const url = settings.apiUrl.replace(/\/$/, "");
    try {
      const response = await fetch(`${url}/targets/${groupId}/stop`, {
        method: 'POST',
        mode: 'cors'
      });
      if (response.ok) {
        toast({ title: "Scan Stop Requested", description: "Request sent to scanner engine." });
      }
    } catch (e) {
      toast({ variant: "destructive", title: "Error", description: "Failed to stop scan." });
    }
  }, [settings?.apiUrl, fetchGroups]);

  return {
    targets: targetGroups,
    selectedTargetId: selectedGroupId,
    setSelectedTargetId: setSelectedGroupId,
    addTarget: addTargetGroup,
    deleteTarget: deleteTargetGroup,
    runScan,
    stopScan,
    runAIAnalysis,
    isAnalyzing,
    isBackendConnected,
    refresh: fetchGroups
  };
}
