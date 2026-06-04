"use client";

import { useState, useEffect, useMemo } from 'react';
import { useScannerStore } from '@/lib/scanner-store';
import { ReconMode, ReconModuleType, Credential, CredentialType, ScanStatus } from '@/lib/types';
import { 
  Plus, 
  Terminal, 
  Shield, 
  Trash2, 
  Play, 
  Square,
  Settings2, 
  Clock,
  LayoutDashboard,
  Network,
  Globe,
  Wifi,
  WifiOff,
  Camera,
  PlusCircle,
  XCircle,
  Layers,
  Link as LinkIcon,
  ShieldEllipsis,
  BrainCircuit,
  Settings,
  Cookie
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
import { WebSurfaceView } from './WebSurfaceView';
import { TLSAnalysisView } from './TLSAnalysisView';
import { URLHarvestingView } from './URLHarvestingView';
import { CORSAuditView } from './CORSAuditView';
import { RiskAnalysisView } from './RiskAnalysisView';
import { CookieAuditView } from './CookieAuditView';
import { Progress } from './ui/progress';
import { Badge } from './ui/badge';
import { formatDistanceToNow } from 'date-fns';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { SettingsDialog } from './SettingsDialog';
import { Switch } from './ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Textarea } from './ui/textarea';
import Image from 'next/image';
import { cn } from '@/lib/utils';

const INITIAL_MODULES: Record<ReconModuleType, boolean> = {
  subdomain_enumeration: true,
  osint: true,
  cert_transparency: true,
  port_scanning: true,
  tech_stack: true,
  api_discovery: true,
  screenshotting: true,
  web_surface_scan: true,
  tls_analysis: true,
  url_harvesting: true,
  cors_audit: true,
  cookie_audit: true,
};

export default function Dashboard() {
  const [mounted, setMounted] = useState(false);
  const { 
    targets: groups, 
    selectedTargetId: selectedGroupId, 
    setSelectedTargetId: setSelectedGroupId, 
    addTarget: addGroup, 
    deleteTarget: deleteGroup, 
    runScan,
    stopScan,
    isBackendConnected
  } = useScannerStore();

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState('');
  const [newHostsRaw, setNewHostsRaw] = useState('');
  const [newMode, setNewMode] = useState<ReconMode>('blackbox');
  const [selectedModules, setSelectedModules] = useState<Record<ReconModuleType, boolean>>(INITIAL_MODULES);
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [selectedChildId, setSelectedChildId] = useState<string | null>(null);

  useEffect(() => {
    setMounted(true);
  }, []);

  const selectedGroup = useMemo(() => groups.find(g => g.id === selectedGroupId), [groups, selectedGroupId]);

  const selectedChild = useMemo(() => {
    if (!selectedGroup) return null;
    if (!selectedChildId) return selectedGroup.childTargets[0] || null;
    return selectedGroup.childTargets.find(c => c.id === selectedChildId) || selectedGroup.childTargets[0] || null;
  }, [selectedGroup, selectedChildId]);

  const handleAddGroup = () => {
    const hosts = newHostsRaw.split('\n').map(h => h.trim()).filter(h => h.length > 0);
    if (hosts.length === 0) return;
    
    const finalName = newGroupName.trim() || `Group ${groups.length + 1}`;
    addGroup(finalName, hosts, newMode, selectedModules, newMode === 'greybox' ? credentials : []);
    
    setNewGroupName('');
    setNewHostsRaw('');
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
      headerName: '',
      username: '',
      password: '',
      notes: '',
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

  const toggleModuleSelection = (module: ReconModuleType) => {
    setSelectedModules(prev => ({ ...prev, [module]: !prev[module] }));
  };

  const getStatusBadge = (status: ScanStatus) => {
    switch (status) {
      case 'running': return <Badge className="bg-primary/20 text-primary border-primary/30 animate-pulse">Running</Badge>;
      case 'completed': return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">Complete</Badge>;
      case 'failed': return <Badge variant="destructive">Failed / Stopped</Badge>;
      default: return <Badge variant="outline">Idle</Badge>;
    }
  };

  if (!mounted) return null;

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
                New Target Group
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-4xl max-h-[90vh] flex flex-col">
              <DialogHeader>
                <DialogTitle>Create New Recon Group</DialogTitle>
              </DialogHeader>
              <Tabs defaultValue="general" className="w-full flex-1 flex flex-col overflow-hidden">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="general">Group Info</TabsTrigger>
                  <TabsTrigger value="auth" disabled={newMode !== 'greybox'}>Authentication</TabsTrigger>
                  <TabsTrigger value="modules">Module Pipeline</TabsTrigger>
                </TabsList>
                
                <TabsContent value="general" className="space-y-4 py-4 overflow-y-auto">
                  <div className="space-y-2">
                    <Label>Group Name</Label>
                    <Input 
                      placeholder="e.g., Client X Infrastructure" 
                      value={newGroupName}
                      onChange={(e) => setNewGroupName(e.target.value)}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Targets (one per line)</Label>
                    <Textarea 
                      placeholder="example.com&#10;api.example.com&#10;192.168.1.1" 
                      className="min-h-[150px] font-code text-sm"
                      value={newHostsRaw}
                      onChange={(e) => setNewHostsRaw(e.target.value)}
                    />
                    <p className="text-[10px] text-muted-foreground">Enter domains, URLs, or IP addresses.</p>
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

                    <div className="grid grid-cols-1 gap-4">
                      {credentials.map((cred) => (
                        <Card key={cred.id} className="border-border/60 bg-card/40">
                          <CardContent className="p-4 space-y-3">
                            <div className="flex items-center justify-between gap-4">
                              <div className="flex-1">
                                <Label className="text-[10px] uppercase font-bold text-muted-foreground">Label</Label>
                                <Input 
                                  className="h-8 text-sm"
                                  value={cred.label} 
                                  onChange={(e) => updateCredential(cred.id, { label: e.target.value || '' })} 
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
                              <Button variant="ghost" size="icon" className="mt-5 h-8 w-8 text-destructive" onClick={() => removeCredential(cred.id)}>
                                <XCircle size={16} />
                              </Button>
                            </div>

                            <div className="grid grid-cols-2 gap-3">
                              {(cred.type === 'custom_header' || cred.type === 'api_key') && (
                                <div className="space-y-1">
                                  <Label className="text-[10px] uppercase font-bold text-muted-foreground">Header Name</Label>
                                  <Input className="h-8 text-sm" placeholder="X-API-Key" value={cred.headerName || ''} onChange={(e) => updateCredential(cred.id, { headerName: e.target.value })} />
                                </div>
                              )}
                              {(cred.type === 'username_password' || cred.type === 'basic_auth') && (
                                <>
                                  <div className="space-y-1">
                                    <Label className="text-[10px] uppercase font-bold text-muted-foreground">Username</Label>
                                    <Input className="h-8 text-sm" value={cred.username || ''} onChange={(e) => updateCredential(cred.id, { username: e.target.value })} />
                                  </div>
                                  <div className="space-y-1">
                                    <Label className="text-[10px] uppercase font-bold text-muted-foreground">Password</Label>
                                    <Input type="password" placeholder="••••••••" className="h-8 text-sm" value={cred.password || ''} onChange={(e) => updateCredential(cred.id, { password: e.target.value })} />
                                  </div>
                                </>
                              )}
                              {cred.type !== 'username_password' && (
                                <div className="col-span-2 space-y-1">
                                  <Label className="text-[10px] uppercase font-bold text-muted-foreground">Value / Secret</Label>
                                  <Input type="password" placeholder="••••••••" className="h-8 text-sm" value={cred.value || ''} onChange={(e) => updateCredential(cred.id, { value: e.target.value })} />
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
                          <Switch checked={selectedModules[key]} onCheckedChange={() => toggleModuleSelection(key)} />
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </TabsContent>
              </Tabs>
              <DialogFooter className="pt-4 border-t border-border">
                <Button variant="outline" onClick={() => setIsAddOpen(false)}>Cancel</Button>
                <Button onClick={handleAddGroup}>Create Group Run</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        <ScrollArea className="flex-1 px-3">
          <div className="space-y-2">
            {groups.map(group => (
              <div 
                key={group.id}
                onClick={() => {
                  setSelectedGroupId(group.id);
                  setSelectedChildId(group.childTargets[0]?.id || null);
                }}
                className={`group p-4 rounded-xl cursor-pointer transition-all duration-200 border ${
                  selectedGroupId === group.id 
                  ? 'bg-primary/10 border-primary/40 shadow-sm' 
                  : 'bg-transparent border-transparent hover:bg-secondary/50'
                }`}
              >
                <div className="flex items-start justify-between mb-1">
                  <div className="space-y-0.5 min-w-0 flex-1">
                    <h3 className="font-bold text-sm truncate pr-2">{group.name}</h3>
                    <p className="text-[10px] text-muted-foreground truncate">{group.childTargets.length} targets</p>
                  </div>
                  <Button 
                    variant="ghost" 
                    size="icon" 
                    className="h-6 w-6 opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-destructive"
                    onClick={(e) => { e.stopPropagation(); deleteGroup(group.id); }}
                  >
                    <Trash2 size={12} />
                  </Button>
                </div>
                <div className="flex items-center gap-2 mt-2">
                   <Badge variant="outline" className={`text-[10px] uppercase font-bold py-0 h-4 ${group.mode === 'greybox' ? 'bg-accent/10 text-accent border-accent/20' : ''}`}>
                    {group.mode}
                   </Badge>
                   <span className="text-[10px] text-muted-foreground">
                    {group.lastRunAt ? formatDistanceToNow(group.lastRunAt, { addSuffix: true }) : 'Never run'}
                   </span>
                </div>
                {group.status === 'running' && (
                  <Progress value={group.progress} className="h-1 mt-3" />
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
        {selectedGroup ? (
          <>
            <header className="p-6 border-b border-border bg-card/10 backdrop-blur-lg flex items-center justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-1">
                  <h2 className="text-2xl font-headline font-bold">{selectedGroup.name}</h2>
                  {getStatusBadge(selectedGroup.status)}
                </div>
                <div className="flex items-center gap-4 text-sm text-muted-foreground">
                  <span className="flex items-center gap-1.5"><Clock size={14} /> Created {new Date(selectedGroup.createdAt).toLocaleDateString()}</span>
                  <span className={`flex items-center gap-1.5 ${selectedGroup.mode === 'greybox' ? 'text-accent font-bold' : ''}`}>
                    {selectedGroup.mode === 'greybox' ? <Shield size={14} /> : <Settings2 size={14} />} 
                    {selectedGroup.mode} Mode
                  </span>
                </div>
                {selectedGroup.status === 'running' && (
                  <div className="mt-4 flex items-center gap-3 max-w-md">
                    <Progress value={selectedGroup.progress} className="h-2 flex-1" />
                    <span className="text-[10px] font-code font-bold text-primary">{selectedGroup.progress}%</span>
                  </div>
                )}
              </div>
              <div className="flex items-center gap-3">
                {selectedGroup.status === 'running' ? (
                  <Button variant="destructive" onClick={() => stopScan(selectedGroup.id)} className="gap-2">
                    <Square size={16} fill="currentColor" /> Stop Group Scan
                  </Button>
                ) : (
                  <Button onClick={() => runScan(selectedGroup.id)} disabled={!isBackendConnected} className="gap-2">
                    <Play size={18} /> Start Group Scan
                  </Button>
                )}
              </div>
            </header>

            <div className="px-6 py-2 border-b border-border bg-secondary/20 flex items-center gap-2 overflow-x-auto no-scrollbar">
              <span className="text-[10px] font-bold text-muted-foreground uppercase mr-2 whitespace-nowrap">Selected Target:</span>
              {selectedGroup.childTargets.map(child => (
                <button
                  key={child.id}
                  onClick={() => setSelectedChildId(child.id)}
                  className={cn(
                    "px-3 py-1.5 rounded-full text-xs transition-all whitespace-nowrap flex items-center gap-2 border",
                    selectedChildId === child.id 
                    ? "bg-primary text-white border-primary shadow-lg" 
                    : "bg-background/50 hover:bg-background border-transparent text-muted-foreground"
                  )}
                >
                  <Globe size={12} />
                  {child.host}
                  {child.status === 'running' && <span className="w-1.5 h-1.5 bg-white rounded-full animate-pulse" />}
                  {child.status === 'completed' && <span className="w-1.5 h-1.5 bg-green-400 rounded-full" />}
                </button>
              ))}
            </div>

            <div className="flex-1 overflow-auto p-6 space-y-6">
              {selectedChild ? (
                <Tabs defaultValue="overview" className="w-full">
                  <TabsList className="bg-secondary/50 p-1 flex-wrap h-auto">
                    <TabsTrigger value="overview" className="gap-2"><LayoutDashboard size={14} /> Overview</TabsTrigger>
                    <TabsTrigger value="risk" className="gap-2"><BrainCircuit size={14} /> AI Analysis</TabsTrigger>
                    <TabsTrigger value="network" className="gap-2"><Network size={14} /> Network</TabsTrigger>
                    <TabsTrigger value="harvesting" className="gap-2"><LinkIcon size={14} /> URL Harvesting</TabsTrigger>
                    <TabsTrigger value="surface" className="gap-2"><Layers size={14} /> Web Surface</TabsTrigger>
                    <TabsTrigger value="cors" className="gap-2"><ShieldEllipsis size={14} /> CORS Audit</TabsTrigger>
                    <TabsTrigger value="cookies" className="gap-2"><Cookie size={14} /> Cookie Audit</TabsTrigger>
                    <TabsTrigger value="tls" className="gap-2"><Shield size={14} /> SSL/TLS</TabsTrigger>
                    <TabsTrigger value="snapshots" className="gap-2"><Camera size={14} /> Snapshots</TabsTrigger>
                    <TabsTrigger value="logs" className="gap-2"><Terminal size={14} /> Live Logs</TabsTrigger>
                  </TabsList>

                  <TabsContent value="overview" className="mt-6 space-y-6">
                    {selectedChild.status === 'idle' && (
                      <div className="flex flex-col items-center justify-center py-20 text-center space-y-4 opacity-50">
                        <Globe size={48} />
                        <h3 className="text-xl font-bold">Awaiting Scan Initiation</h3>
                        <p className="text-sm">Start the group run to see results for {selectedChild.host}.</p>
                      </div>
                    )}
                    {selectedChild.status !== 'idle' && (
                      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                        <TerminalLogs logs={selectedChild.results?.logs || []} />
                        <div className="space-y-6">
                          {selectedChild.results?.riskAnalysis && (
                             <div className="p-6 rounded-xl border border-primary/30 bg-primary/5">
                               <div className="flex items-center justify-between mb-4">
                                 <h4 className="text-sm font-semibold uppercase tracking-wider text-primary">AI Threat Assessment</h4>
                                 <span className="text-4xl font-bold font-code text-primary">{selectedChild.results.riskAnalysis.riskScore}</span>
                               </div>
                               <Progress value={selectedChild.results.riskAnalysis.riskScore} className="h-2 mb-4" />
                               <p className="text-xs text-muted-foreground leading-relaxed">{selectedChild.results.riskAnalysis.riskSummary}</p>
                             </div>
                          )}
                          <Card className="bg-secondary/10 border-border/50">
                            <CardContent className="p-4">
                              <h4 className="text-[10px] font-bold text-muted-foreground uppercase tracking-widest mb-4">Target Stats</h4>
                              <div className="grid grid-cols-2 gap-4">
                                <div className="p-3 rounded bg-background/50 border border-border">
                                  <span className="block text-xl font-bold font-code">{selectedChild.results?.subdomains?.length || 0}</span>
                                  <span className="text-[10px] text-muted-foreground">SUBDOMAINS</span>
                                </div>
                                <div className="p-3 rounded bg-background/50 border border-border">
                                  <span className="block text-xl font-bold font-code">{selectedChild.results?.portScanResults?.length || 0}</span>
                                  <span className="text-[10px] text-muted-foreground">PORTS</span>
                                </div>
                              </div>
                            </CardContent>
                          </Card>
                        </div>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="risk" className="mt-6">
                    {selectedChild.results?.riskAnalysis ? (
                      <RiskAnalysisView data={selectedChild.results.riskAnalysis} />
                    ) : (
                      <div className="py-20 text-center opacity-40">
                         {selectedChild.status === 'completed' ? "AI Analysis is being generated..." : "Waiting for scan to complete..."}
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="network" className="mt-6 space-y-6">
                    {selectedChild.results?.portScanResults?.length ? (
                      <Card>
                        <CardHeader><CardTitle className="text-lg">Services</CardTitle></CardHeader>
                        <CardContent>
                          <Table>
                            <TableHeader><TableRow><TableHead>Port</TableHead><TableHead>Service</TableHead><TableHead>State</TableHead><TableHead>Version</TableHead></TableRow></TableHeader>
                            <TableBody>
                              {selectedChild.results.portScanResults.map((res, i) => (
                                <TableRow key={i}>
                                  <TableCell className="font-code text-primary">{res.port}</TableCell>
                                  <TableCell className="capitalize">{res.service}</TableCell>
                                  <TableCell><Badge variant={res.state === 'open' ? 'default' : 'outline'}>{res.state}</Badge></TableCell>
                                  <TableCell className="text-muted-foreground font-code text-xs">{res.version || 'Unknown'}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </CardContent>
                      </Card>
                    ) : <div className="py-20 text-center opacity-40">No network data yet.</div>}
                  </TabsContent>

                  <TabsContent value="harvesting" className="mt-6">
                    {selectedChild.results?.urlHarvesting ? (
                      <URLHarvestingView data={selectedChild.results.urlHarvesting} />
                    ) : <div className="py-20 text-center opacity-40">No URL data harvested yet.</div>}
                  </TabsContent>

                  <TabsContent value="surface" className="mt-6">
                    {selectedChild.results?.webSurface ? (
                      <WebSurfaceView data={selectedChild.results.webSurface} />
                    ) : <div className="py-20 text-center opacity-40">Awaiting Web Surface scan...</div>}
                  </TabsContent>

                  <TabsContent value="cors" className="mt-6">
                    {selectedChild.results?.cors_audit ? (
                      <CORSAuditView data={selectedChild.results.cors_audit} />
                    ) : <div className="py-20 text-center opacity-40">Awaiting CORS Audit...</div>}
                  </TabsContent>

                  <TabsContent value="cookies" className="mt-6">
                    {selectedChild.results?.cookie_audit ? (
                      <CookieAuditView data={selectedChild.results.cookie_audit} />
                    ) : <div className="py-20 text-center opacity-40">Awaiting Cookie Audit...</div>}
                  </TabsContent>

                  <TabsContent value="tls" className="mt-6">
                    {selectedChild.results?.tlsData ? (
                      <TLSAnalysisView data={selectedChild.results.tlsData} />
                    ) : <div className="py-20 text-center opacity-40">Awaiting SSL/TLS scan...</div>}
                  </TabsContent>

                  <TabsContent value="snapshots" className="mt-6">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      {selectedChild.results?.screenshots?.map((url, i) => (
                        <Card key={i} className="overflow-hidden bg-black/50 aspect-video relative">
                          <Image src={url} alt={`Snapshot ${i + 1}`} fill className="object-cover" />
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="logs" className="mt-6">
                    <div className="h-[calc(100vh-320px)]">
                      <TerminalLogs logs={selectedChild.results?.logs || []} />
                    </div>
                  </TabsContent>
                </Tabs>
              ) : (
                <div className="py-20 text-center text-muted-foreground">Select a child target to view results.</div>
              )}
            </div>
          </>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center p-12 text-center">
             <Shield size={80} className="text-primary opacity-20 mb-6" />
             <h2 className="text-3xl font-bold mb-4">CypherRecon Enterprise</h2>
             <p className="text-muted-foreground max-w-md">Select a target group of create a new multi-target run to begin analysis.</p>
          </div>
        )}
      </main>

      <SettingsDialog open={isSettingsOpen} onOpenChange={setIsSettingsOpen} />
    </div>
  );
}
