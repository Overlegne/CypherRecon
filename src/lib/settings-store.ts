"use client";

import { useState, useEffect, useCallback } from 'react';
import { AppSettings } from './types';

const DEFAULT_SETTINGS: AppSettings = {
  apiKeys: {
    shodan: '',
    virustotal: '',
    censys: '',
    hunterio: '',
    securitytrails: '',
  },
  scanDefaults: {
    intensity: 'T4',
    threads: 10,
    followRedirects: true,
    userAgent: 'CypherRecon/1.0 (Ethical Recon Engine)',
  }
};

export function useSettingsStore() {
  const [settings, setSettings] = useState<AppSettings>(DEFAULT_SETTINGS);

  useEffect(() => {
    const saved = localStorage.getItem('cypherrecon_settings');
    if (saved) {
      try {
        setSettings(JSON.parse(saved));
      } catch (e) {
        console.error("Failed to load settings", e);
      }
    }
  }, []);

  const updateSettings = useCallback((updates: Partial<AppSettings>) => {
    setSettings(prev => {
      const next = { ...prev, ...updates };
      localStorage.setItem('cypherrecon_settings', JSON.stringify(next));
      return next;
    });
  }, []);

  const updateApiKey = useCallback((key: keyof AppSettings['apiKeys'], value: string) => {
    setSettings(prev => {
      const next = {
        ...prev,
        apiKeys: { ...prev.apiKeys, [key]: value }
      };
      localStorage.setItem('cypherrecon_settings', JSON.stringify(next));
      return next;
    });
  }, []);

  return { settings, updateSettings, updateApiKey };
}
