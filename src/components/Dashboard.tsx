
"use client";

import { useState } from 'react';
import { useScannerStore } from '@/lib/scanner-store';
import { Target, ReconMode, ReconModuleType, Credential, CredentialType } from '@/lib/types';
import { 
  Plus, 
  Terminal, 
  Shield, 
  Trash2, 
  Play, 
  Square,
  Settings2, 
  FileText, 
  Globe, 
  ArrowRight,
  Loader2,
  Clock,
  LayoutDashboard,
  Search,
  Activity,
  Network,
  Cpu,
  Unplug,
  Settings,
  ChevronRight,
  ExternalLink,
  Code,
  Users,
  AlertTriangle,
  Link as LinkIcon,
  Camera,
  Maximize2,
  Wifi,
  WifiOff,
  Key,
  Lock,
  PlusCircle,
  XCircle,
  Eye,
  EyeOff,
  Layers
} from 'lucide-react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { 
  Dialog, 
  DialogContent, 
  DialogHeader, 
  DialogTitle, 
  DialogTrigger,
  DialogFooter 
} from './ui/dialog';
import { RadioGroup, RadioGroupItem } from './ui/radio-group';
import { ScrollArea } from './ui/scroll-area';
import { TerminalLogs } from './TerminalLogs';
import { ModuleConfig } from './ModuleConfig';
import { RiskAnalysisView } from './RiskAnalysisView';
import { WebSurfaceView } from './WebSurfaceView';
import { Progress } from './ui/progress';
import { Badge } from './ui/badge';
import { formatDistanceToNow } from 'date-fns';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { SettingsDialog } from './SettingsDialog';
import { Switch } from './ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Textarea } from './ui/textarea';
import Image from 'next/image';

const INITIAL_MODULES: Record<ReconModuleType, boolean> = {
  subdomain_enumeration: true,
  osint: true,
  cert_transparency: true,
  port_scanning: true,
  tech_stack: true,
  api_discovery: true,
  screenshotting: true,
  web_surface_scan: true,
};

export default function Dashboard() {
  const { 
    targets, 
    selectedTargetId, 
    setSelectedTargetId, 
    addTarget, 
    deleteTarget, 
    runScan,
    stopScan,
    isBackendConnected
  } = useScannerStore();

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [newHost, setNewHost] = useState('');
  const [newMode, setNewMode] = useState<ReconMode>('blackbox');
  const [selectedModules, setSelectedModules] = useState<Record<ReconModuleType, boolean>>(INITIAL_MODULES);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [showSecrets, setShowSecrets] = useState<Record<string, boolean>>({});

  const selectedTarget = targets.find(t => t.id === selectedTargetId);

  const handleAddTarget = () => {
    if (!newHost) return;
    addTarget(newHost, newMode, selectedModules, newMode === 'greybox' ? credentials : []);
    setNewHost('');
    setNewMode('blackbox');
    setSelectedModules(INITIAL_MODULES);
    setCredentials([]);
    setIsAddOpen(false);
  };

  const addCredential = () => {
    const newCred: Credential = {
      id: Math.random().toString(36).substr(2, 9),
      type: 'api_key',
      label: `Credential ${credentials.length + 1}`,
      value: '',
      enabled: true
    };
    setCredentials([...credentials, newCred]);
  };

  const updateCredential = (id: string, updates: Partial<Credential>) => {
    setCredentials(credentials.map(c => c.id === id ? { ...c, ...updates } : c));
  };

  const removeCredential = (id: string) => {
    setCredentials(credentials.filter(c => c.id !== id));
  };

  const toggleSecret = (id: string) => {
    setShowSecrets(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleModuleSelection = (module: ReconModuleType) => {
    setSelectedModules(prev => ({ ...prev, [module]: !prev[module] }));
  };

  const getStatusBadge = (status: Target['status']) => {
    switch (status) {
      case 'running': return <Badge className="bg-primary/20 text-primary border-primary/30 animate-pulse">Running</Badge>;
      case 'completed': return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">Complete</Badge>;
      case 'failed': return <Badge variant="destructive">Failed / Stopped</Badge>;
      default: return <Badge variant="outline">Idle</Badge>;
    }
  };

  const getOsintIcon = (type: string) => {
    switch (type) {
      case 'code': return <Code className="text-blue-400" size={18} />;
      case 'social': return <Users className="text-purple-400" size={18} />;
      case 'leak': return <AlertTriangle className="text-red-400" size={18} />;
      default: return <Unplug className="text-yellow-500" size={18} />;
    }
  };

  return (
    <div className="flex h-screen bg-background overflow-hidden">
      {/* Sidebar */}
      <aside className="w-80 border-r border-border flex flex-col bg-card/30 backdrop-blur-xl">
        <div className="p-6 border-b border-border flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-lg bg-primary shadow-lg shadow-primary/20">
                <Shield className="text-white" size={20} />
              </div>
              <h1 className="font-headline font-bold text-xl tracking-tight">Cypher<span className="text-primary">Recon</span></h1>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isBackendConnected ? (
              <Badge variant="outline" className="text-[10px] bg-green-500/10 text-green-400 border-green-500/20 gap-1.5">
                <Wifi size={10} /> ENGINE ONLINE
              </Badge>
            ) : (
              <Badge variant="outline" className="text-[10px] bg-destructive/10 text-destructive border-destructive/20 gap-1.5">
                <WifiOff size={10} /> ENGINE OFFLINE
              </Badge>
            )}
          </div>
        </div>

        <div className="p-4">
          <Dialog open={isAddOpen} onOpenChange={setIsAddOpen}>
            <DialogTrigger asChild>
              <Button className="w-full justify-start gap-2 bg-primary hover:bg-primary/90 text-white shadow-lg shadow-primary/20" size="lg">
                <Plus size={18} />
                New Target
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col">
              <DialogHeader>
                <DialogTitle>Add New Recon Target</DialogTitle>
              </DialogHeader>
              <Tabs defaultValue="general" className="w-full flex-1 flex flex-col overflow-hidden">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="general">Target Info</TabsTrigger>
                  <TabsTrigger value="auth" disabled={newMode !== 'greybox'}>Authentication</TabsTrigger>
                  <TabsTrigger value="modules">Module Pipeline</TabsTrigger>
                </TabsList>
                
                <TabsContent value="general" className="space-y-4 py-4 overflow-y-auto">
                  <div className="space-y-2">
                    <Label>Domain or IP Address</Label>
                    <Input 
                      placeholder="example.com or 192.168.1.1" 
                      value={newHost}
                      onChange={(e) => setNewHost(e.target.value)}
                    />
                  </div>
                  <div className="space-y-3">
                    <Label>Recon Mode</Label>
                    <RadioGroup value={newMode} onValueChange={(v) => setNewMode(v as ReconMode)}>
                      <div className="flex items-center space-x-2 p-3 rounded-lg border border-border hover:bg-secondary/20 transition-colors cursor-pointer" onClick={() => setNewMode('blackbox')}>
                        <RadioGroupItem value="blackbox" id="blackbox" />
                        <div className="flex-1">
                          <Label htmlFor="blackbox" className="font-semibold block cursor-pointer">Blackbox</Label>
                          <span className="text-[10px] text-muted-foreground">External discovery only. No prior knowledge required.</span>
                        </div>
                      </div>
                      <div className="flex items-center space-x-2 p-3 rounded-lg border border-border hover:bg-secondary/20 transition-colors cursor-pointer" onClick={() => setNewMode('greybox')}>
                        <RadioGroupItem value="greybox" id="greybox" />
                        <div className="flex-1">
                          <Label htmlFor="greybox" className="font-semibold block cursor-pointer">Greybox</Label>
                          <span className="text-[10px] text-muted-foreground">Includes authenticated entrypoints and deeper insights.</span>
                        </div>
                      </div>
                    </RadioGroup>
                  </div>
                </TabsContent>

                <TabsContent value="auth" className="py-4 overflow-y-auto flex-1">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <h4 className="font-semibold">Greybox Authentication</h4>
                        <p className="text-xs text-muted-foreground">Add credentials for authenticated scanning and discovery.</p>
                      </div>
                      <Button variant="outline" size="sm" onClick={addCredential} className="gap-2">
                        <PlusCircle size={14} /> Add Credential
                      </Button>
                    </div>

                    {credentials.length === 0 && (
                      <div className="text-center py-8 border-2 border-dashed border-border rounded-xl opacity-50">
                        <Key size={32} className="mx-auto mb-2 text-muted-foreground" />
                        <p className="text-sm">No credentials added for this Greybox target.</p>
                      </div>
                    )}

                    <div className="grid grid-cols-1 gap-4">
                      {credentials.map((cred) => (
                        <Card key={cred.id} className="border-border/60 bg-card/40">
                          <CardContent className="p-4 space-y-3">
                            <div className="flex items-center justify-between gap-4">
                              <div className="flex-1">
                                <Label className="text-[10px] uppercase font-bold text-muted-foreground">Label</Label>
                                <Input 
                                  size={1}
                                  className="h-8 text-sm"
                                  value={cred.label} 
                                  onChange={(e) => updateCredential(cred.id, { label: e.target.value })} 
                                />
                              </div>
                              <div className="w-[180px]">
                                <Label className="text-[10px] uppercase font-bold text-muted-foreground">Type</Label>
                                <Select 
                                  value={cred.type} 
                                  onValueChange={(v) => updateCredential(cred.id, { type: v as CredentialType })}
                                >
                                  <SelectTrigger className="h-8 text-sm">
                                    <SelectValue />
                                  </SelectTrigger>
                                  <SelectContent>
                                    <SelectItem value="api_key">API Key</SelectItem>
                                    <SelectItem value="bearer_token">Bearer Token</SelectItem>
                                    <SelectItem value="jwt">JWT Token</SelectItem>
                                    <SelectItem value="cookie">Cookie</SelectItem>
                                    <SelectItem value="username_password">User/Pass</SelectItem>
                                    <SelectItem value="basic_auth">Basic Auth</SelectItem>
                                    <SelectItem value="custom_header">Custom Header</SelectItem>
                                    <SelectItem value="query_param">Query Param</SelectItem>
                                  </SelectContent>
                                </Select>
                              </div>
                              <Button 
                                variant="ghost" 
                                size="icon" 
                                className="mt-5 h-8 w-8 text-destructive" 
                                onClick={() => removeCredential(cred.id)}
                              >
                                <XCircle size={16} />
                              </Button>
                            </div>

                            <div className="grid grid-cols-2 gap-3">
                              {(cred.type === 'custom_header' || cred.type === 'api_key') && (
                                <div className="space-y-1">
                                  <Label className="text-[10px] uppercase font-bold text-muted-foreground">Header Name</Label>
                                  <Input 
                                    className="h-8 text-sm"
                                    placeholder="X-API-Key" 
                                    value={cred.headerName} 
                                    onChange={(e) => updateCredential(cred.id, { headerName: e.target.value })}
                                  />
                                </div>
                              )}
                              {(cred.type === 'username_password' || cred.type === 'basic_auth') && (
                                <div className="space-y-1">
                                  <Label className="text-[10px] uppercase font-bold text-muted-foreground">Username</Label>
                                  <Input 
                                    className="h-8 text-sm"
                                    value={cred.username} 
                                    onChange={(e) => updateCredential(cred.id, { username: e.target.value })}
                                  />
                                </div>
                              )}
                              {(cred.type === 'username_password' || cred.type === 'basic_auth') && (
                                <div className="space-y-1">
                                  <Label className="text-[10px] uppercase font-bold text-muted-foreground">Password</Label>
                                  <div className="relative">
                                    <Input 
                                      type={showSecrets[cred.id] ? "text" : "password"}
                                      className="h-8 text-sm pr-8"
                                      value={cred.password} 
                                      onChange={(e) => updateCredential(cred.id, { password: e.target.value })}
                                    />
                                    <Button 
                                      variant="ghost" 
                                      size="icon" 
                                      className="absolute right-0 top-0 h-8 w-8" 
                                      onClick={() => toggleSecret(cred.id)}
                                    >
                                      {showSecrets[cred.id] ? <EyeOff size={12} /> : <Eye size={12} />}
                                    </Button>
                                  </div>
                                </div>
                              )}
                              {cred.type !== 'username_password' && (
                                <div className="col-span-2 space-y-1">
                                  <Label className="text-[10px] uppercase font-bold text-muted-foreground">Value / Secret</Label>
                                  <div className="relative">
                                    <Input 
                                      type={showSecrets[cred.id] ? "text" : "password"}
                                      className="h-8 text-sm pr-8"
                                      value={cred.value} 
                                      onChange={(e) => updateCredential(cred.id, { value: e.target.value })}
                                    />
                                    <Button 
                                      variant="ghost" 
                                      size="icon" 
                                      className="absolute right-0 top-0 h-8 w-8" 
                                      onClick={() => toggleSecret(cred.id)}
                                    >
                                      {showSecrets[cred.id] ? <EyeOff size={12} /> : <Eye size={12} />}
                                    </Button>
                                  </div>
                                </div>
                              )}
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="modules" className="py-4 overflow-y-auto">
                  <ScrollArea className="h-[300px] pr-4">
                    <div className="space-y-3">
                      {(Object.keys(selectedModules) as ReconModuleType[]).map((key) => (
                        <div key={key} className="flex items-center justify-between p-3 rounded-lg border border-border bg-card/50">
                          <div className="space-y-0.5">
                            <Label className="text-sm font-medium capitalize">{key.replace(/_/g, ' ')}</Label>
                            <p className="text-[10px] text-muted-foreground">Enable specialized discovery for this component.</p>
                          </div>
                          <Switch 
                            checked={selectedModules[key]} 
                            onCheckedChange={() => toggleModuleSelection(key)} 
                          />
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </TabsContent>
              </Tabs>
              <DialogFooter className="pt-4 border-t border-border">
                <Button variant="outline" onClick={() => setIsAddOpen(false)}>Cancel</Button>
                <Button onClick={handleAddTarget}>Create Sequence</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        <ScrollArea className="flex-1 px-3">
          <div className="space-y-2">
            {targets.length === 0 && (
              <div className="flex flex-col items-center justify-center p-8 text-center text-muted-foreground opacity-40">
                <Globe size={40} className="mb-2" />
                <p className="text-sm">No targets added yet</p>
              </div>
            )}
            {targets.map(target => (
              <div 
                key={target.id}
                onClick={() => setSelectedTargetId(target.id)}
                className={`group p-4 rounded-xl cursor-pointer transition-all duration-200 border ${
                  selectedTargetId === target.id 
                  ? 'bg-primary/10 border-primary/40 shadow-sm' 
                  : 'bg-transparent border-transparent hover:bg-secondary/50'
                }`}
              >
                <div className="flex items-start justify-between mb-1">
                  <h3 className="font-medium text-sm truncate max-w-[150px]">{target.host}</h3>
                  <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button 
                      variant="ghost" 
                      size="icon" 
                      className="h-6 w-6 text-muted-foreground hover:text-destructive"
                      onClick={(e) => { e.stopPropagation(); deleteTarget(target.id); }}
                    >
                      <Trash2 size={12} />
                    </Button>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                   <Badge variant="outline" className={`text-[10px] uppercase font-bold py-0 h-4 border-muted-foreground/30 ${target.mode === 'greybox' ? 'bg-accent/10 text-accent border-accent/20' : ''}`}>
                    {target.mode}
                   </Badge>
                   <span className="text-[10px] text-muted-foreground">
                    {target.lastRunAt ? formatDistanceToNow(target.lastRunAt, { addSuffix: true }) : 'Never run'}
                   </span>
                </div>
                {target.status === 'running' && (
                  <div className="mt-3 space-y-1">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-primary font-medium">{target.activeModule?.replace(/_/g, ' ')}</span>
                      <span>{target.progress}%</span>
                    </div>
                    <Progress value={target.progress} className="h-1" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </ScrollArea>

        <div className="p-4 border-t border-border mt-auto">
          <Button 
            variant="ghost" 
            className="w-full justify-start gap-2 text-muted-foreground hover:text-foreground"
            onClick={() => setIsSettingsOpen(true)}
          >
            <Settings size={18} />
            System Settings
          </Button>
        </div>
      </aside>

      <main className="flex-1 flex flex-col min-w-0">
        {selectedTarget ? (
          <>
            <header className="p-6 border-b border-border bg-card/10 backdrop-blur-lg flex items-center justify-between">
              <div>
                <div className="flex items-center gap-3 mb-1">
                  <h2 className="text-2xl font-headline font-bold">{selectedTarget.host}</h2>
                  {getStatusBadge(selectedTarget.status)}
                </div>
                <div className="flex items-center gap-4 text-sm text-muted-foreground">
                  <span className="flex items-center gap-1.5"><Clock size={14} /> Created {new Date(selectedTarget.createdAt).toLocaleDateString()}</span>
                  <span className={`flex items-center gap-1.5 ${selectedTarget.mode === 'greybox' ? 'text-accent font-bold' : ''}`}>
                    {selectedTarget.mode === 'greybox' ? <Lock size={14} /> : <Settings2 size={14} />} 
                    {selectedTarget.mode} Mode
                    {selectedTarget.mode === 'greybox' && ` (${selectedTarget.credentials?.length || 0} Credentials)`}
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {selectedTarget.status === 'running' ? (
                  <Button 
                    variant="destructive"
                    onClick={() => stopScan(selectedTarget.id)}
                    className="gap-2"
                  >
                    <Square size={16} fill="currentColor" />
                    Stop Scan
                  </Button>
                ) : (
                  <Button 
                    onClick={() => runScan(selectedTarget.id)} 
                    disabled={!isBackendConnected}
                    className={`gap-2 ${isBackendConnected ? 'bg-accent text-white hover:bg-accent/90' : 'bg-muted text-muted-foreground'}`}
                  >
                    <Play size={18} />
                    {selectedTarget.status === 'completed' || selectedTarget.status === 'failed' ? 'Restart Sequence' : 'Start Sequence'}
                  </Button>
                )}
              </div>
            </header>

            <div className="flex-1 overflow-auto p-6 space-y-6">
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="bg-secondary/50 p-1 flex-wrap h-auto">
                  <TabsTrigger value="overview" className="gap-2"><LayoutDashboard size={14} /> Overview</TabsTrigger>
                  <TabsTrigger value="network" className="gap-2"><Network size={14} /> Network</TabsTrigger>
                  <TabsTrigger value="discovery" className="gap-2"><Search size={14} /> Discovery</TabsTrigger>
                  <TabsTrigger value="surface" className="gap-2"><Layers size={14} /> Web Surface</TabsTrigger>
                  <TabsTrigger value="snapshots" className="gap-2"><Camera size={14} /> Snapshots</TabsTrigger>
                  <TabsTrigger value="modules" className="gap-2"><Settings2 size={14} /> Modules</TabsTrigger>
                  <TabsTrigger value="logs" className="gap-2"><Terminal size={14} /> Live Logs</TabsTrigger>
                  <TabsTrigger value="report" className="gap-2" disabled={!selectedTarget.results?.riskAnalysis}><FileText size={14} /> Risk Analysis</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="mt-6 space-y-6">
                  {selectedTarget.status === 'idle' && (
                    <div className="flex flex-col items-center justify-center py-20 text-center space-y-4">
                      <div className="p-6 rounded-full bg-primary/5 border border-primary/10">
                        {selectedTarget.mode === 'greybox' ? <Lock size={48} className="text-accent opacity-50" /> : <Globe size={48} className="text-primary opacity-50" />}
                      </div>
                      <div className="max-w-md">
                        <h3 className="text-xl font-bold mb-2">Ready to initiate {selectedTarget.mode} reconnaissance</h3>
                        {!isBackendConnected && (
                          <div className="mb-4 p-3 rounded-lg bg-destructive/10 border border-destructive/20 text-destructive text-xs flex items-center gap-2">
                            <WifiOff size={14} /> Backend scanner service is currently offline.
                          </div>
                        )}
                        <p className="text-muted-foreground mb-6">
                          {selectedTarget.mode === 'greybox' 
                            ? `Authenticated scan mode. Will use ${selectedTarget.credentials?.length || 0} stored credentials for deep analysis.`
                            : "Standard unauthenticated scan mode. Will map the public attack surface."}
                        </p>
                        <Button 
                          onClick={() => runScan(selectedTarget.id)} 
                          size="lg" 
                          className="gap-2"
                          disabled={!isBackendConnected}
                        >
                          Execute Workflow <ArrowRight size={18} />
                        </Button>
                      </div>
                    </div>
                  )}

                  {selectedTarget.status !== 'idle' && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                      <div className="space-y-6">
                        <div className="p-6 rounded-xl border border-border bg-card/50">
                          <h4 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-4">Discovery Findings</h4>
                          <div className="grid grid-cols-2 gap-4">
                            <div className="p-4 rounded-lg bg-secondary/30 border border-border">
                              <span className="block text-2xl font-bold font-code">{selectedTarget.results?.subdomains?.length || 0}</span>
                              <span className="text-xs text-muted-foreground uppercase">Subdomains</span>
                            </div>
                            <div className="p-4 rounded-lg bg-secondary/30 border border-border">
                              <span className="block text-2xl font-bold font-code">{selectedTarget.results?.portScanResults?.length || 0}</span>
                              <span className="text-xs text-muted-foreground uppercase">Active Ports</span>
                            </div>
                          </div>
                        </div>
                        <TerminalLogs logs={selectedTarget.results?.logs || []} />
                      </div>
                      <div className="space-y-6">
                        {selectedTarget.results?.riskAnalysis && (
                           <div className="p-6 rounded-xl border border-primary/30 bg-primary/5">
                             <div className="flex items-center justify-between mb-4">
                               <h4 className="text-sm font-semibold uppercase tracking-wider text-primary">Initial AI Risk Score</h4>
                               <span className="text-4xl font-bold font-code text-primary">{selectedTarget.results.riskAnalysis.riskScore}</span>
                             </div>
                             <Progress value={selectedTarget.results.riskAnalysis.riskScore} className="h-2 mb-4" />
                             <p className="text-xs text-muted-foreground leading-relaxed">
                               {selectedTarget.results.riskAnalysis.riskSummary}
                             </p>
                           </div>
                        )}
                        {selectedTarget.mode === 'greybox' && (
                          <Card className="border-accent/30 bg-accent/5">
                            <CardHeader className="pb-2">
                              <CardTitle className="text-sm flex items-center gap-2">
                                <Key size={16} className="text-accent" />
                                Active Credentials for Run
                              </CardTitle>
                            </CardHeader>
                            <CardContent>
                              <div className="space-y-2">
                                {selectedTarget.credentials?.map((c, i) => (
                                  <div key={i} className="flex items-center justify-between text-xs p-2 rounded bg-background/40">
                                    <span className="font-medium">{c.label}</span>
                                    <Badge variant="outline" className="h-4 text-[9px]">{c.type.replace('_', ' ')}</Badge>
                                  </div>
                                ))}
                              </div>
                            </CardContent>
                          </Card>
                        )}
                      </div>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="network" className="mt-6 space-y-6">
                  {selectedTarget.results?.portScanResults?.length ? (
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg flex items-center gap-2">
                          <Network size={20} className="text-primary" />
                          Service Version Scan results (nmap -sCV)
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead>Port</TableHead>
                              <TableHead>Service</TableHead>
                              <TableHead>State</TableHead>
                              <TableHead>Version Info</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {selectedTarget.results?.portScanResults?.map((res, i) => (
                              <TableRow key={i}>
                                <TableCell className="font-code font-bold text-primary">{res.port}</TableCell>
                                <TableCell className="capitalize">{res.service}</TableCell>
                                <TableCell>
                                  <Badge variant={res.state === 'open' ? 'default' : 'outline'} className={res.state === 'open' ? 'bg-green-500 hover:bg-green-600' : ''}>
                                    {res.state}
                                  </Badge>
                                </TableCell>
                                <TableCell className="text-muted-foreground font-code text-xs">{res.version || 'Unknown'}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </CardContent>
                    </Card>
                  ) : (
                    <div className="py-20 text-center opacity-40">Awaiting network scan results...</div>
                  )}
                </TabsContent>

                <TabsContent value="discovery" className="mt-6 space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg">Subdomains Map</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          {selectedTarget.results?.subdomains?.length ? selectedTarget.results.subdomains.map((sub, i) => (
                            <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-secondary/20 border border-border">
                              <span className="font-code text-sm">{sub}</span>
                              <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => window.open(`https://${sub}`, '_blank')}>
                                <Globe size={14} />
                              </Button>
                            </div>
                          )) : <p className="text-xs text-muted-foreground italic">No subdomains discovered yet.</p>}
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg">OSINT & Public Leaks</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          {selectedTarget.results?.osintData?.map((finding, i) => (
                            <div key={i} className="flex flex-col gap-3 p-4 rounded-xl border border-yellow-500/20 bg-yellow-500/5 group">
                              <div className="flex items-start justify-between">
                                <div className="flex gap-3">
                                  <div className="mt-0.5">{getOsintIcon(finding.type)}</div>
                                  <div className="space-y-1">
                                    <h4 className="text-sm font-bold flex items-center gap-2">
                                      {finding.label}
                                      {finding.type === 'leak' && <Badge variant="destructive" className="h-4 text-[9px] uppercase">Critical Leak</Badge>}
                                    </h4>
                                    <p className="text-xs text-muted-foreground leading-relaxed">
                                      {finding.description}
                                    </p>
                                  </div>
                                </div>
                                {finding.url && (
                                  <Button 
                                    variant="outline" 
                                    size="icon" 
                                    className="h-8 w-8 shrink-0 hover:bg-yellow-500/10"
                                    onClick={() => window.open(finding.url, '_blank')}
                                  >
                                    <ExternalLink size={14} />
                                  </Button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>

                <TabsContent value="surface" className="mt-6 space-y-6">
                  {selectedTarget.results?.webSurface ? (
                    <WebSurfaceView data={selectedTarget.results.webSurface} />
                  ) : (
                    <div className="py-20 text-center opacity-40">Awaiting Web Surface security scan...</div>
                  )}
                </TabsContent>

                <TabsContent value="snapshots" className="mt-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {selectedTarget.results?.screenshots?.length ? selectedTarget.results.screenshots.map((url, i) => (
                      <Card key={i} className="overflow-hidden group">
                        <div className="relative aspect-video bg-black/50">
                          <Image 
                            src={url} 
                            alt={`Visual Snapshot ${i + 1}`} 
                            fill 
                            className="object-cover transition-transform group-hover:scale-105"
                          />
                          <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 transition-opacity flex items-center justify-center">
                            <Button variant="outline" size="sm" className="gap-2 bg-background/50 backdrop-blur" onClick={() => window.open(url, '_blank')}>
                              <Maximize2 size={14} /> View Fullsize
                            </Button>
                          </div>
                        </div>
                      </Card>
                    )) : (
                      <div className="col-span-full py-20 text-center opacity-40">No snapshots captured yet.</div>
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="modules" className="mt-6">
                  <ModuleConfig target={selectedTarget} onToggle={(mod) => {}} />
                </TabsContent>

                <TabsContent value="logs" className="mt-6">
                  <div className="h-[calc(100vh-320px)]">
                    <TerminalLogs logs={selectedTarget.results?.logs || []} />
                  </div>
                </TabsContent>

                <TabsContent value="report" className="mt-6">
                  {selectedTarget.results?.riskAnalysis && (
                    <RiskAnalysisView data={selectedTarget.results.riskAnalysis} />
                  )}
                </TabsContent>
              </Tabs>
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
             <div className="relative mb-8">
               <div className="absolute inset-0 bg-primary/20 blur-3xl rounded-full" />
               <div className="relative p-8 rounded-full bg-card border border-border shadow-2xl">
                 <Shield size={80} className="text-primary" />
               </div>
             </div>
             <h2 className="text-3xl font-headline font-bold mb-4 tracking-tight">CypherRecon Workflow Engine</h2>
             <p className="text-muted-foreground max-w-md mb-8 leading-relaxed">
               Select a target from the sidebar or add a new one to begin your reconnaissance sequence. 
             </p>
          </div>
        )}
      </main>

      <SettingsDialog open={isSettingsOpen} onOpenChange={setIsSettingsOpen} />
    </div>
  );
}
