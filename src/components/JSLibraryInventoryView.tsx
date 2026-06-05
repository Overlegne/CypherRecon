"use client";

import { JSLibraryInventoryData, JSLibrary } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';
import { ShieldCheck, ShieldAlert, AlertTriangle, FileCode, Code2, Globe, ExternalLink, Info, Bug } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { Button } from './ui/button';
import { cn } from '@/lib/utils';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip';

export function JSLibraryInventoryView({ data }: { data: JSLibraryInventoryData }) {
  const getStatusBadge = (library: JSLibrary) => {
    switch (library.status) {
      case 'high_risk':
        return <Badge variant="destructive" className="gap-1"><ShieldAlert size={12} /> HIGH RISK</Badge>;
      case 'possibly_outdated':
        return <Badge className="bg-yellow-500 text-black hover:bg-yellow-600 gap-1"><AlertTriangle size={12} /> OUTDATED</Badge>;
      case 'ok':
        return <Badge className="bg-green-500 hover:bg-green-600 gap-1"><ShieldCheck size={12} /> SECURE</Badge>;
      default:
        return <Badge variant="outline" className="gap-1"><Info size={12} /> UNKNOWN</Badge>;
    }
  };

  const getEOLBadge = (status?: string) => {
    if (status === 'eol') return <Badge variant="destructive" className="h-5 text-[10px]">EOL</Badge>;
    if (status === 'supported') return <Badge className="h-5 text-[10px] bg-green-500/20 text-green-400 border-green-500/30">SUPPORTED</Badge>;
    return <Badge variant="outline" className="h-5 text-[10px] opacity-40">UNKNOWN</Badge>;
  };

  const getConfidenceBadge = (score: number) => {
    const color = score > 0.8 ? "text-green-500" : score > 0.5 ? "text-yellow-500" : "text-red-500";
    return (
      <span className={cn("text-[10px] font-bold uppercase", color)}>
        {Math.round(score * 100)}% Match
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-secondary/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code">{data.summary.js_files_tested}</span>
            <span className="text-xs text-muted-foreground uppercase">JS Files Analyzed</span>
          </CardContent>
        </Card>
        <Card className="bg-primary/5 border-primary/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-primary">{data.summary.unique_libraries}</span>
            <span className="text-xs text-muted-foreground uppercase">Libraries Found</span>
          </CardContent>
        </Card>
        <Card className="bg-yellow-500/5 border-yellow-500/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-yellow-500">{data.summary.possibly_outdated}</span>
            <span className="text-xs text-muted-foreground uppercase">Outdated</span>
          </CardContent>
        </Card>
        <Card className="bg-destructive/5 border-destructive/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-destructive">{data.summary.high_risk}</span>
            <span className="text-xs text-muted-foreground uppercase">Vulnerable</span>
          </CardContent>
        </Card>
      </div>

      {/* Findings Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <FileCode size={18} className="text-primary" />
            JavaScript Framework & Library Inventory
          </CardTitle>
          <CardDescription>
            Detection of frontend technologies, version lifecycles, and security advisories.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader className="bg-muted/30">
              <TableRow>
                <TableHead>Library</TableHead>
                <TableHead>Current / Latest</TableHead>
                <TableHead>Lifecycle</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Intelligence</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.libraries.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="py-10 text-center text-muted-foreground italic">
                    No JavaScript libraries identified during analysis.
                  </TableCell>
                </TableRow>
              ) : (
                data.libraries.map((lib, idx) => (
                  <TableRow key={idx} className={cn("group hover:bg-muted/20", lib.status === 'high_risk' && "bg-destructive/5")}>
                    <TableCell>
                      <div className="flex flex-col">
                        <div className="flex items-center gap-2">
                          <Code2 size={14} className="text-primary" />
                          <span className="font-bold text-sm">{lib.name}</span>
                        </div>
                        <span className="text-[10px] text-muted-foreground truncate max-w-[200px] mt-0.5" title={lib.file}>
                          {lib.file.split('/').pop()}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <span className="font-code text-xs bg-secondary px-1.5 py-0.5 rounded">
                          {lib.version || "???"}
                        </span>
                        <span className="text-muted-foreground">/</span>
                        <span className="text-[10px] text-primary/80 font-bold">
                          {lib.latest_version || "Unknown"}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      {getEOLBadge(lib.eol_status)}
                    </TableCell>
                    <TableCell>{getStatusBadge(lib)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-2">
                        {lib.vuln_url && (
                          <TooltipProvider>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button 
                                  variant="outline" 
                                  size="icon" 
                                  className="h-8 w-8 text-destructive hover:bg-destructive/10" 
                                  onClick={() => window.open(lib.vuln_url, '_blank')}
                                >
                                  <Bug size={14} />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>View Snyk Advisories</TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        )}
                        <Button variant="ghost" size="icon" className="h-8 w-8 opacity-40 hover:opacity-100" onClick={() => window.open(lib.file, '_blank')}>
                          <ExternalLink size={14} />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Advisory Section */}
      {data.summary.possibly_outdated > 0 && (
        <div className="p-4 rounded-xl border border-yellow-500/30 bg-yellow-500/5 flex gap-4">
          <Info className="text-yellow-500 shrink-0" size={24} />
          <div className="space-y-1">
            <h4 className="font-bold text-sm text-yellow-500 uppercase tracking-wide">Supply Chain Hardening Recommended</h4>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Verouderde JavaScript libraries zijn een van de meest voorkomende entry-points voor aanvallers via bekende CVE's. 
              <strong> Advies:</strong> Update de gemarkeerde libraries naar de nieuwste stabiele versie en overweeg het gebruik van Subresource Integrity (SRI).
            </p>
          </div>
        </div>
      )}
    </div>
  );
}