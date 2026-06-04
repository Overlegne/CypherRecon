"use client";

import { useState } from 'react';
import { useScannerStore } from '@/lib/scanner-store';
import { Target, ReconMode, ReconModuleType } from '@/lib/types';
import { 
  Plus, 
  Terminal, 
  Shield, 
  Trash2, 
  Play, 
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
  AlertTriangle
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
import { Progress } from './ui/progress';
import { Badge } from './ui/badge';
import { formatDistanceToNow } from 'date-fns';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { SettingsDialog } from './SettingsDialog';
import { Switch } from './ui/switch';

const INITIAL_MODULES: Record<ReconModuleType, boolean> = {
  subdomain_enumeration: true,
  osint: true,
  cert_transparency: true,
  port_scanning: true,
  tech_stack: true,
  api_discovery: true,
  screenshotting: false,
};

export default function Dashboard() {
  const { 
    targets, 
    selectedTargetId, 
    setSelectedTargetId, 
    addTarget, 
    deleteTarget, 
    toggleModule, 
    runScan 
  } = useScannerStore();

  const [isAddOpen, setIsAddOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [newHost, setNewHost] = useState('');
  const [newMode, setNewMode] = useState<ReconMode>('blackbox');
  const [selectedModules, setSelectedModules] = useState<Record<ReconModuleType, boolean>>(INITIAL_MODULES);

  const selectedTarget = targets.find(t => t.id === selectedTargetId);

  const handleAddTarget = () => {
    if (!newHost) return;
    addTarget(newHost, newMode, selectedModules);
    setNewHost('');
    setSelectedModules(INITIAL_MODULES);
    setIsAddOpen(false);
  };

  const toggleModuleSelection = (module: ReconModuleType) => {
    setSelectedModules(prev => ({ ...prev, [module]: !prev[module] }));
  };

  const getStatusBadge = (status: Target['status']) => {
    switch (status) {
      case 'running': return <Badge className="bg-primary/20 text-primary border-primary/30 animate-pulse">Running</Badge>;
      case 'completed': return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">Complete</Badge>;
      case 'failed': return <Badge variant="destructive">Failed</Badge>;
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
        <div className="p-6 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="p-2 rounded-lg bg-primary shadow-lg shadow-primary/20">
              <Shield className="text-white" size={20} />
            </div>
            <h1 className="font-headline font-bold text-xl tracking-tight">Cypher<span className="text-primary">Recon</span></h1>
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
            <DialogContent className="max-w-xl">
              <DialogHeader>
                <DialogTitle>Add New Recon Target</DialogTitle>
              </DialogHeader>
              <Tabs defaultValue="general" className="w-full">
                <TabsList className="grid w-full grid-cols-2">
                  <TabsTrigger value="general">Target Info</TabsTrigger>
                  <TabsTrigger value="modules">Module Pipeline</TabsTrigger>
                </TabsList>
                
                <TabsContent value="general" className="space-y-4 py-4">
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
                          <span className="text-[10px] text-muted-foreground">Includes potential credentialed entrypoints and deeper insights.</span>
                        </div>
                      </div>
                    </RadioGroup>
                  </div>
                </TabsContent>

                <TabsContent value="modules" className="py-4">
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
              <DialogFooter>
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
                   <Badge variant="outline" className="text-[10px] uppercase font-bold py-0 h-4 border-muted-foreground/30">
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

        {/* Sidebar Footer with Settings */}
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

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0">
        {selectedTarget ? (
          <>
            {/* Header */}
            <header className="p-6 border-b border-border bg-card/10 backdrop-blur-lg flex items-center justify-between">
              <div>
                <div className="flex items-center gap-3 mb-1">
                  <h2 className="text-2xl font-headline font-bold">{selectedTarget.host}</h2>
                  {getStatusBadge(selectedTarget.status)}
                </div>
                <div className="flex items-center gap-4 text-sm text-muted-foreground">
                  <span className="flex items-center gap-1.5"><Clock size={14} /> Created {new Date(selectedTarget.createdAt).toLocaleDateString()}</span>
                  <span className="flex items-center gap-1.5"><Settings2 size={14} /> {selectedTarget.mode} Mode</span>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Button 
                  onClick={() => runScan(selectedTarget.id)} 
                  disabled={selectedTarget.status === 'running'}
                  className="gap-2 bg-accent text-white hover:bg-accent/90"
                >
                  {selectedTarget.status === 'running' ? (
                    <Loader2 size={18} className="animate-spin" />
                  ) : (
                    <Play size={18} />
                  )}
                  {selectedTarget.status === 'completed' ? 'Re-run Scan' : 'Start Sequence'}
                </Button>
              </div>
            </header>

            {/* Content Area */}
            <div className="flex-1 overflow-auto p-6 space-y-6">
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="bg-secondary/50 p-1 flex-wrap h-auto">
                  <TabsTrigger value="overview" className="gap-2"><LayoutDashboard size={14} /> Overview</TabsTrigger>
                  <TabsTrigger value="network" className="gap-2" disabled={!selectedTarget.results?.portScanResults}><Network size={14} /> Network</TabsTrigger>
                  <TabsTrigger value="discovery" className="gap-2" disabled={!selectedTarget.results?.subdomains}><Search size={14} /> Discovery</TabsTrigger>
                  <TabsTrigger value="surface" className="gap-2" disabled={!selectedTarget.results?.techStack}><Cpu size={14} /> Web Surface</TabsTrigger>
                  <TabsTrigger value="modules" className="gap-2"><Settings2 size={14} /> Modules</TabsTrigger>
                  <TabsTrigger value="logs" className="gap-2"><Terminal size={14} /> Live Logs</TabsTrigger>
                  <TabsTrigger value="report" className="gap-2" disabled={!selectedTarget.results?.riskAnalysis}><FileText size={14} /> Risk Analysis</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="mt-6 space-y-6">
                  {selectedTarget.status === 'idle' && (
                    <div className="flex flex-col items-center justify-center py-20 text-center space-y-4">
                      <div className="p-6 rounded-full bg-primary/5 border border-primary/10">
                        <Globe size={48} className="text-primary opacity-50" />
                      </div>
                      <div className="max-w-md">
                        <h3 className="text-xl font-bold mb-2">Ready to initiate reconnaissance</h3>
                        <p className="text-muted-foreground mb-6">Configure your active modules and start the scan to map the attack surface and analyze risks.</p>
                        <Button onClick={() => runScan(selectedTarget.id)} size="lg" className="gap-2">
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
                            <div className="p-4 rounded-lg bg-secondary/30 border border-border hover:border-primary/50 transition-colors cursor-pointer">
                              <span className="block text-2xl font-bold font-code">{selectedTarget.results?.subdomains?.length || 0}</span>
                              <span className="text-xs text-muted-foreground uppercase">Subdomains</span>
                            </div>
                            <div className="p-4 rounded-lg bg-secondary/30 border border-border hover:border-primary/50 transition-colors cursor-pointer">
                              <span className="block text-2xl font-bold font-code">{selectedTarget.results?.portScanResults?.length || 0}</span>
                              <span className="text-xs text-muted-foreground uppercase">Active Ports</span>
                            </div>
                            <div className="p-4 rounded-lg bg-secondary/30 border border-border hover:border-primary/50 transition-colors cursor-pointer">
                              <span className="block text-2xl font-bold font-code">{selectedTarget.results?.apiEndpoints?.length || 0}</span>
                              <span className="text-xs text-muted-foreground uppercase">API Paths</span>
                            </div>
                            <div className="p-4 rounded-lg bg-secondary/30 border border-border hover:border-primary/50 transition-colors cursor-pointer">
                              <span className="block text-2xl font-bold font-code">{selectedTarget.results?.techStack?.length || 0}</span>
                              <span className="text-xs text-muted-foreground uppercase">Tech Stack</span>
                            </div>
                          </div>
                        </div>
                        
                        <TerminalLogs logs={selectedTarget.results?.logs || []} />
                      </div>

                      <div className="space-y-6">
                        <div className="p-6 rounded-xl border border-border bg-card/50">
                          <h4 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-4">Quick Tech Profile</h4>
                          <div className="flex flex-wrap gap-2">
                            {selectedTarget.results?.techStack?.map((tech, i) => (
                              <Badge key={i} variant="secondary" className="px-3 py-1 font-medium">{tech}</Badge>
                            )) || <p className="text-xs text-muted-foreground italic">No data yet...</p>}
                          </div>
                        </div>

                        {selectedTarget.results?.riskAnalysis && (
                           <div className="p-6 rounded-xl border border-primary/30 bg-primary/5">
                             <div className="flex items-center justify-between mb-4">
                               <h4 className="text-sm font-semibold uppercase tracking-wider text-primary">Initial AI Risk Score</h4>
                               <span className="text-4xl font-bold font-code text-primary">{selectedTarget.results.riskAnalysis.riskScore}</span>
                             </div>
                             <Progress value={selectedTarget.results.riskAnalysis.riskScore} className="h-2 mb-4" />
                             <p className="text-xs text-muted-foreground leading-relaxed line-clamp-3">
                               {selectedTarget.results.riskAnalysis.riskSummary}
                             </p>
                           </div>
                        )}
                      </div>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="network" className="mt-6 space-y-6">
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
                </TabsContent>

                <TabsContent value="discovery" className="mt-6 space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-lg">Subdomains Map</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          {selectedTarget.results?.subdomains?.map((sub, i) => (
                            <div key={i} className="flex items-center justify-between p-3 rounded-lg bg-secondary/20 border border-border">
                              <span className="font-code text-sm">{sub}</span>
                              <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => window.open(`https://${sub}`, '_blank')}>
                                <Globe size={14} />
                              </Button>
                            </div>
                          ))}
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
                              {finding.url && (
                                <div className="pl-7 mt-1">
                                  <button 
                                    onClick={() => window.open(finding.url, '_blank')}
                                    className="text-[10px] text-primary hover:underline flex items-center gap-1 font-code truncate max-w-full"
                                  >
                                    {finding.url}
                                  </button>
                                </div>
                              )}
                            </div>
                          ))}
                          {(!selectedTarget.results?.osintData || selectedTarget.results.osintData.length === 0) && (
                            <p className="text-sm text-muted-foreground italic">No public leaks discovered in current sequence.</p>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>

                <TabsContent value="surface" className="mt-6 space-y-6">
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <Card className="lg:col-span-1">
                      <CardHeader>
                        <CardTitle className="text-lg">Technological Stack</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex flex-col gap-2">
                          {selectedTarget.results?.techStack?.map((tech, i) => (
                            <div key={i} className="flex items-center gap-2 p-2 rounded bg-secondary/40 border border-border">
                              <div className="w-2 h-2 rounded-full bg-primary" />
                              <span className="text-sm font-medium">{tech}</span>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>

                    <Card className="lg:col-span-2">
                      <CardHeader>
                        <CardTitle className="text-lg">Endpoints Discovered</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {selectedTarget.results?.apiEndpoints?.map((endpoint, i) => (
                            <div key={i} className="group flex items-center justify-between p-2 rounded bg-card border border-border hover:border-primary/40 transition-colors">
                              <code className="text-xs text-primary">{endpoint}</code>
                              <Badge variant="outline" className="text-[9px] opacity-0 group-hover:opacity-100 transition-opacity uppercase">API</Badge>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </TabsContent>

                <TabsContent value="modules" className="mt-6">
                  <div className="max-w-4xl space-y-6">
                    <div className="p-4 bg-primary/10 border border-primary/20 rounded-lg text-sm text-primary flex items-start gap-3">
                      <Settings2 className="shrink-0 mt-0.5" size={18} />
                      <p>Adjust these settings before initiating a scan. Deep port scans (-p-) with version detection (-sV) are enabled by default for the Port Scanning module.</p>
                    </div>
                    <ModuleConfig target={selectedTarget} onToggle={(mod) => toggleModule(selectedTarget.id, mod)} />
                  </div>
                </TabsContent>

                <TabsContent value="logs" className="mt-6">
                  <div className="h-[calc(100vh-320px)]">
                    <TerminalLogs logs={selectedTarget.results?.logs || []} />
                  </div>
                </TabsContent>

                <TabsContent value="report" className="mt-6">
                  {selectedTarget.results?.riskAnalysis ? (
                    <RiskAnalysisView data={selectedTarget.results.riskAnalysis} />
                  ) : (
                    <div className="flex flex-col items-center justify-center py-20 text-center opacity-40">
                      <FileText size={48} className="mb-4" />
                      <p>Run a full scan to generate risk analysis.</p>
                    </div>
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
               Automated discovery and AI-powered risk assessment await.
             </p>
             <div className="grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-2xl">
               <div className="p-4 rounded-xl border border-border bg-secondary/20">
                 <Search size={24} className="text-primary mb-3 mx-auto" />
                 <h4 className="font-semibold text-sm mb-1">Deep Discovery</h4>
                 <p className="text-[11px] text-muted-foreground">Map subdomains, API paths, and tech stacks automatically.</p>
               </div>
               <div className="p-4 rounded-xl border border-border bg-secondary/20">
                 <Activity size={24} className="text-accent mb-3 mx-auto" />
                 <h4 className="font-semibold text-sm mb-1">Live Telemetry</h4>
                 <p className="text-[11px] text-muted-foreground">Monitor real-time logs and port scanning progress.</p>
               </div>
               <div className="p-4 rounded-xl border border-border bg-secondary/20">
                 <FileText size={24} className="text-green-500 mb-3 mx-auto" />
                 <h4 className="font-semibold text-sm mb-1">AI Risk Assessment</h4>
                 <p className="text-[11px] text-muted-foreground">Get instant risk scores and vulnerability summaries.</p>
               </div>
             </div>
          </div>
        )}
      </main>

      {/* Global Settings Dialog */}
      <SettingsDialog open={isSettingsOpen} onOpenChange={setIsSettingsOpen} />
    </div>
  );
}
