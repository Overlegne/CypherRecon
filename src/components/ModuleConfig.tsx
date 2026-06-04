"use client";

import { ReconModuleType, Target } from '@/lib/types';
import { Switch } from './ui/switch';
import { Label } from './ui/label';
import { Shield, Search, Lock, Activity, Layers, Share2, Camera } from 'lucide-react';

const MODULE_INFO: Record<ReconModuleType, { label: string, icon: any, desc: string }> = {
  subdomain_enumeration: { label: 'Subdomains', icon: Search, desc: 'Find hidden sub-levels' },
  osint: { label: 'OSINT', icon: Share2, desc: 'Public data collection' },
  cert_transparency: { label: 'Cert Logs', icon: Shield, desc: 'Transparency log checks' },
  port_scanning: { label: 'Port Scan', icon: Activity, desc: 'Active service discovery' },
  tech_stack: { label: 'Tech Stack', icon: Layers, desc: 'Detect frameworks/tools' },
  api_discovery: { label: 'API Endpoints', icon: Lock, desc: 'Map hidden API paths' },
  screenshotting: { label: 'Snapshots', icon: Camera, desc: 'Visual app capture' },
};

export function ModuleConfig({ target, onToggle }: { target: Target, onToggle: (module: ReconModuleType) => void }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
      {(Object.keys(MODULE_INFO) as ReconModuleType[]).map((key) => {
        const info = MODULE_INFO[key];
        const Icon = info.icon;
        const isActive = target.modules[key];
        
        return (
          <div 
            key={key} 
            className={`flex items-start gap-3 p-3 rounded-lg border transition-all duration-200 cursor-pointer ${isActive ? 'bg-primary/5 border-primary/20' : 'bg-transparent border-border opacity-60'}`}
            onClick={() => onToggle(key)}
          >
            <div className={`p-2 rounded-md ${isActive ? 'bg-primary text-white' : 'bg-secondary text-muted-foreground'}`}>
              <Icon size={16} />
            </div>
            <div className="flex-1 space-y-1">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium leading-none cursor-pointer">{info.label}</Label>
                <Switch 
                  checked={isActive}
                  onCheckedChange={() => onToggle(key)}
                  onClick={(e) => e.stopPropagation()}
                />
              </div>
              <p className="text-[10px] text-muted-foreground line-clamp-1">{info.desc}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}