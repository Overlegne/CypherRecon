"use client";

import { useState } from 'react';
import { useSettingsStore } from '@/lib/settings-store';
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogDescription,
  DialogFooter
} from './ui/dialog';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Button } from './ui/button';
import { Switch } from './ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Key, Settings2, ShieldCheck, Zap } from 'lucide-react';

export function SettingsDialog({ open, onOpenChange }: { open: boolean, onOpenChange: (open: boolean) => void }) {
  const { settings, updateSettings, updateApiKey } = useSettingsStore();

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings2 size={20} className="text-primary" />
            Global System Settings
          </DialogTitle>
          <DialogDescription>
            Configure your API keys and global scanning engine preferences.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="api" className="w-full mt-4">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="api" className="gap-2"><Key size={14} /> Intelligence Keys</TabsTrigger>
            <TabsTrigger value="engine" className="gap-2"><Zap size={14} /> Scan Engine</TabsTrigger>
          </TabsList>

          <TabsContent value="api" className="space-y-4 py-4">
            <div className="grid gap-4">
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="shodan" className="text-right text-xs">Shodan API</Label>
                <Input
                  id="shodan"
                  type="password"
                  value={settings.apiKeys.shodan}
                  onChange={(e) => updateApiKey('shodan', e.target.value)}
                  className="col-span-3 font-code"
                  placeholder="Enter API Key"
                />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="vt" className="text-right text-xs">VirusTotal</Label>
                <Input
                  id="vt"
                  type="password"
                  value={settings.apiKeys.virustotal}
                  onChange={(e) => updateApiKey('virustotal', e.target.value)}
                  className="col-span-3 font-code"
                  placeholder="Enter API Key"
                />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="censys" className="text-right text-xs">Censys ID</Label>
                <Input
                  id="censys"
                  type="password"
                  value={settings.apiKeys.censys}
                  onChange={(e) => updateApiKey('censys', e.target.value)}
                  className="col-span-3 font-code"
                  placeholder="Enter API Key"
                />
              </div>
              <div className="grid grid-cols-4 items-center gap-4">
                <Label htmlFor="hunter" className="text-right text-xs">Hunter.io</Label>
                <Input
                  id="hunter"
                  type="password"
                  value={settings.apiKeys.hunterio}
                  onChange={(e) => updateApiKey('hunterio', e.target.value)}
                  className="col-span-3 font-code"
                  placeholder="Enter API Key"
                />
              </div>
            </div>
            <div className="p-3 bg-primary/5 border border-primary/20 rounded-lg flex gap-3 items-start mt-4">
              <ShieldCheck className="text-primary shrink-0 mt-0.5" size={16} />
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                API keys are stored locally in your browser's encrypted cache. They are only transmitted to the respective service providers during active scan modules.
              </p>
            </div>
          </TabsContent>

          <TabsContent value="engine" className="space-y-6 py-4">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Nmap Scan Intensity</Label>
                  <p className="text-[10px] text-muted-foreground">Adjust timing templates (T1-T5) for evasion or speed.</p>
                </div>
                <Select 
                  value={settings.scanDefaults.intensity} 
                  onValueChange={(v) => updateSettings({ 
                    scanDefaults: { ...settings.scanDefaults, intensity: v as any } 
                  })}
                >
                  <SelectTrigger className="w-[120px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="T1">T1 (Sneaky)</SelectItem>
                    <SelectItem value="T2">T2 (Polite)</SelectItem>
                    <SelectItem value="T3">T3 (Normal)</SelectItem>
                    <SelectItem value="T4">T4 (Aggressive)</SelectItem>
                    <SelectItem value="T5">T5 (Insane)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Concurrency Threads</Label>
                  <p className="text-[10px] text-muted-foreground">Max simultaneous connections per target.</p>
                </div>
                <Input 
                  type="number" 
                  className="w-20" 
                  value={settings.scanDefaults.threads}
                  onChange={(e) => updateSettings({ 
                    scanDefaults: { ...settings.scanDefaults, threads: parseInt(e.target.value) } 
                  })}
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Follow HTTP Redirects</Label>
                  <p className="text-[10px] text-muted-foreground">Automatically traverse 301/302 responses.</p>
                </div>
                <Switch 
                  checked={settings.scanDefaults.followRedirects}
                  onCheckedChange={(checked) => updateSettings({ 
                    scanDefaults: { ...settings.scanDefaults, followRedirects: checked } 
                  })}
                />
              </div>

              <div className="space-y-1.5">
                <Label>Default User-Agent</Label>
                <Input 
                  className="font-code text-xs" 
                  value={settings.scanDefaults.userAgent}
                  onChange={(e) => updateSettings({ 
                    scanDefaults: { ...settings.scanDefaults, userAgent: e.target.value } 
                  })}
                />
              </div>
            </div>
          </TabsContent>
        </Tabs>

        <DialogFooter>
          <Button onClick={() => onOpenChange(false)}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
