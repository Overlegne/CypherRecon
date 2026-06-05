"use client";

import { WebSurfaceData, WebHeader } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';
import { ShieldCheck, AlertCircle, Info, ShieldAlert, Globe, Link as LinkIcon, Layers, Shield as ShieldIcon } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './ui/tabs';
import { TechnologyInventoryView } from './TechnologyInventoryView';

export function WebSurfaceView({ data }: { data: WebSurfaceData }) {
  const getStatusBadge = (status: WebHeader['status']) => {
    switch (status) {
      case 'ok': return <Badge className="bg-green-500 hover:bg-green-600 gap-1"><ShieldCheck size={10} /> OK</Badge>;
      case 'missing': return <Badge variant="destructive" className="gap-1"><AlertCircle size={10} /> MISSING</Badge>;
      case 'weak': return <Badge className="bg-yellow-500 text-black hover:bg-yellow-600 gap-1"><ShieldAlert size={10} /> WEAK</Badge>;
      case 'info': return <Badge variant="secondary" className="gap-1"><Info size={10} /> INFO</Badge>;
      default: return null;
    }
  };

  const getSeverityColor = (severity: WebHeader['severity']) => {
    switch (severity) {
      case 'high': return 'text-red-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-blue-500';
      default: return 'text-muted-foreground';
    }
  };

  // Group headers by their associated URL
  const groupedHeaders = data.headers.reduce((acc, header) => {
    const url = header.url || 'Primary Target';
    if (!acc[url]) acc[url] = [];
    acc[url].push(header);
    return acc;
  }, {} as Record<string, WebHeader[]>);

  const urls = Object.keys(groupedHeaders);

  return (
    <div className="space-y-6">
      <Tabs defaultValue="headers" className="w-full">
        <TabsList className="grid w-full grid-cols-2 max-w-[400px]">
          <TabsTrigger value="headers" className="gap-2">
            <ShieldIcon size={14} /> Security Headers
          </TabsTrigger>
          <TabsTrigger value="inventory" className="gap-2">
            <Layers size={14} /> Tech Inventory
          </TabsTrigger>
        </TabsList>

        <TabsContent value="headers" className="space-y-6 mt-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="bg-secondary/20">
              <CardContent className="pt-6 text-center">
                <span className="block text-3xl font-bold font-code">{data.summary.tested}</span>
                <span className="text-xs text-muted-foreground uppercase">Headers Tested</span>
              </CardContent>
            </Card>
            <Card className="bg-green-500/5 border-green-500/20">
              <CardContent className="pt-6 text-center">
                <span className="block text-3xl font-bold font-code text-green-500">{data.summary.ok}</span>
                <span className="text-xs text-muted-foreground uppercase">Healthy</span>
              </CardContent>
            </Card>
            <Card className="bg-yellow-500/5 border-yellow-500/20">
              <CardContent className="pt-6 text-center">
                <span className="block text-3xl font-bold font-code text-yellow-500">{data.summary.weak}</span>
                <span className="text-xs text-muted-foreground uppercase">Weak Policy</span>
              </CardContent>
            </Card>
            <Card className="bg-destructive/5 border-destructive/20">
              <CardContent className="pt-6 text-center">
                <span className="block text-3xl font-bold font-code text-destructive">{data.summary.missing}</span>
                <span className="text-xs text-muted-foreground uppercase">Critical Missing</span>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-8">
            {urls.map((url, idx) => (
              <div key={idx} className="space-y-6">
                <Card className="border-border/60">
                  <CardHeader className="pb-3 border-b border-border/40 bg-secondary/10">
                    <CardTitle className="text-lg flex items-center gap-2">
                      <LinkIcon size={18} className="text-primary" />
                      <span className="font-code text-sm break-all">{url}</span>
                    </CardTitle>
                    <CardDescription>
                      Security header posture for this endpoint.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="p-0">
                    <Table>
                      <TableHeader>
                        <TableRow className="bg-muted/30">
                          <TableHead className="w-[250px]">Security Header</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead>Value</TableHead>
                          <TableHead className="text-right">Risk Level</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {groupedHeaders[url].map((header, hIdx) => (
                          <TableRow key={hIdx} className="group hover:bg-muted/20">
                            <TableCell className="font-medium text-sm">{header.name}</TableCell>
                            <TableCell>{getStatusBadge(header.status)}</TableCell>
                            <TableCell className="max-w-[300px]">
                              <div className="font-code text-[11px] truncate text-muted-foreground" title={header.value || ''}>
                                {header.value || <span className="italic opacity-30">Not Set</span>}
                              </div>
                            </TableCell>
                            <TableCell className="text-right">
                              <span className={`text-[10px] uppercase font-bold ${getSeverityColor(header.severity)}`}>
                                {header.severity !== 'none' ? header.severity : '-'}
                              </span>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                {/* Local Recommendations for this URL */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {groupedHeaders[url]
                    .filter(h => h.status !== 'ok' && h.status !== 'info')
                    .map((h, i) => (
                      <div key={i} className="p-4 rounded-xl border border-border bg-card/50 flex gap-4 transition-colors hover:border-primary/20">
                        <div className={`mt-1 shrink-0 ${getSeverityColor(h.severity)}`}>
                          <ShieldAlert size={20} />
                        </div>
                        <div className="space-y-1 overflow-hidden">
                          <h4 className="font-bold text-sm truncate">{h.name}</h4>
                          <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2">
                            {h.recommendation || 'Essential security header missing or misconfigured.'}
                          </p>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="inventory" className="mt-6">
          {data.technology_inventory ? (
            <TechnologyInventoryView data={data.technology_inventory} />
          ) : (
            <div className="py-20 text-center opacity-40">Awaiting Technology Fingerprinting...</div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}