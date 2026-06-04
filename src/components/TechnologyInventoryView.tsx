"use client";

import { TechnologyInventoryData, TechDetection } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';
import { ShieldCheck, ShieldAlert, AlertTriangle, Cpu, Globe, Info, Search } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { cn } from '@/lib/utils';

export function TechnologyInventoryView({ data }: { data: TechnologyInventoryData }) {
  const getStatusBadge = (tech: TechDetection) => {
    switch (tech.status) {
      case 'up_to_date':
        return <Badge className="bg-green-500 hover:bg-green-600 gap-1"><ShieldCheck size={12} /> UP TO DATE</Badge>;
      case 'possibly_outdated':
        return <Badge className="bg-yellow-500 text-black hover:bg-yellow-600 gap-1"><AlertTriangle size={12} /> OUTDATED</Badge>;
      case 'vulnerable_hint':
        return <Badge variant="destructive" className="gap-1"><ShieldAlert size={12} /> RISKY</Badge>;
      default:
        return <Badge variant="outline" className="gap-1"><Info size={12} /> UNKNOWN</Badge>;
    }
  };

  const getRiskColor = (risk: TechDetection['risk']) => {
    switch (risk) {
      case 'critical': return 'text-red-600 font-bold';
      case 'high': return 'text-red-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-blue-500';
      default: return 'text-muted-foreground';
    }
  };

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-secondary/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code">{data.summary.found}</span>
            <span className="text-xs text-muted-foreground uppercase">Tech Detected</span>
          </CardContent>
        </Card>
        <Card className="bg-green-500/5 border-green-500/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-green-500">{data.summary.up_to_date}</span>
            <span className="text-xs text-muted-foreground uppercase">Up to Date</span>
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
            <span className="block text-3xl font-bold font-code text-destructive">{data.summary.vulnerable_hint}</span>
            <span className="text-xs text-muted-foreground uppercase">Risky</span>
          </CardContent>
        </Card>
      </div>

      {/* Tech Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Cpu size={18} className="text-primary" />
            Stack Fingerprinting & Inventory
          </CardTitle>
          <CardDescription>
            Overview of detected frameworks, servers, and tools used by the application.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader className="bg-muted/30">
              <TableRow>
                <TableHead>Technology</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Risk</TableHead>
                <TableHead className="text-right">Evidence</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.technologies.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="py-10 text-center text-muted-foreground italic">
                    No significant technologies fingerprinted yet.
                  </TableCell>
                </TableRow>
              ) : (
                data.technologies.map((tech, idx) => (
                  <TableRow key={idx} className="group hover:bg-muted/20">
                    <TableCell>
                      <div className="font-bold flex items-center gap-2">
                        <Globe size={14} className="text-muted-foreground" />
                        {tech.name}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-[10px] uppercase">{tech.type}</Badge>
                    </TableCell>
                    <TableCell>
                      <code className="text-xs bg-secondary px-1.5 py-0.5 rounded">{tech.version || 'Unknown'}</code>
                    </TableCell>
                    <TableCell>{getStatusBadge(tech)}</TableCell>
                    <TableCell>
                      <span className={cn("text-[10px] uppercase font-bold", getRiskColor(tech.risk))}>
                        {tech.risk}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex flex-wrap justify-end gap-1">
                        {tech.evidence.map((ev, i) => (
                          <span key={i} className="text-[9px] bg-primary/10 text-primary px-1 rounded flex items-center gap-1">
                            <Search size={8} /> {ev}
                          </span>
                        ))}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
