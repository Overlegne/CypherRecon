"use client";

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
import { Key, Settings2, ShieldCheck, Zap, Globe } from 'lucide-react';

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
            Configure your local backend and API credentials.
          </DialogDescription>
        </DialogHeader>

        <Tabs defaultValue="engine" className="w-full mt-4">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="engine" className="gap-2"><Zap size={14} /> Scan Engine</TabsTrigger>
            <TabsTrigger value="api" className="gap-2"><Key size={14} /> Intelligence Keys</TabsTrigger>
          </TabsList>

          <TabsContent value="engine" className="space-y-6 py-4">
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="apiUrl" className="flex items-center gap-2">
                  <Globe size={14} className="text-primary" />
                  Local Backend API URL
                </Label>
                <Input 
                  id="apiUrl"
                  placeholder="http://localhost:5000"
                  value={settings.apiUrl}
                  onChange={(e) => updateSettings({ apiUrl: e.target.value })}
                  className="font-code"
                />
                <p className="text-[10px] text-muted-foreground italic">Point this to your local Python/Go scanner service.</p>
              </div>

              <div className="flex items-center justify-between pt-2">
                <div className="space-y-0.5">
                  <Label>Nmap Scan Intensity</Label>
                  <p className="text-[10px] text-muted-foreground">Adjust timing templates (T1-T5).</p>
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
            </div>
          </TabsContent>

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
            </div>
            <div className="p-3 bg-primary/5 border border-primary/20 rounded-lg flex gap-3 items-start mt-4">
              <ShieldCheck className="text-primary shrink-0 mt-0.5" size={16} />
              <p className="text-[11px] text-muted-foreground leading-relaxed">
                Credentials are saved locally. Ensure your backend service is configured to receive these keys for authenticated modules.
              </p>
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
