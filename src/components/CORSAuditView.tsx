"use client";

import { CORSAuditData, CORSFinding } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';
import { ShieldCheck, ShieldAlert, AlertTriangle, Globe, Lock, Unlock, Server } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { cn } from '@/lib/utils';

export function CORSAuditView({ data }: { data: CORSAuditData }) {
  const getStatusBadge = (finding: CORSFinding) => {
    switch (finding.status) {
      case 'high':
        return <Badge variant="destructive" className="gap-1"><ShieldAlert size={12} /> HIGH RISK</Badge>;
      case 'permissive':
        return <Badge className="bg-yellow-500 text-black hover:bg-yellow-600 gap-1"><Unlock size={12} /> PERMISSIVE</Badge>;
      case 'safe':
        return <Badge className="bg-green-500 hover:bg-green-600 gap-1"><ShieldCheck size={12} /> SAFE</Badge>;
      default:
        return <Badge variant="outline">UNKNOWN</Badge>;
    }
  };

  const getSeverityColor = (severity: CORSFinding['severity']) => {
    switch (severity) {
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
            <span className="block text-3xl font-bold font-code">{data.summary.tested_endpoints}</span>
            <span className="text-xs text-muted-foreground uppercase">Endpoints Tested</span>
          </CardContent>
        </Card>
        <Card className="bg-green-500/5 border-green-500/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-green-500">{data.summary.safe}</span>
            <span className="text-xs text-muted-foreground uppercase">Secure</span>
          </CardContent>
        </Card>
        <Card className="bg-yellow-500/5 border-yellow-500/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-yellow-500">{data.summary.permissive}</span>
            <span className="text-xs text-muted-foreground uppercase">Permissive</span>
          </CardContent>
        </Card>
        <Card className="bg-destructive/5 border-destructive/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-destructive">{data.summary.high_risk}</span>
            <span className="text-xs text-muted-foreground uppercase">High Risk</span>
          </CardContent>
        </Card>
      </div>

      {/* Findings Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <Server size={18} className="text-primary" />
            CORS Configuration Analysis
          </CardTitle>
          <CardDescription>
            Audit of cross-origin resource sharing headers across discovered endpoints.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader className="bg-muted/30">
              <TableRow>
                <TableHead>Endpoint URL</TableHead>
                <TableHead>Tested Origin</TableHead>
                <TableHead>ACAO Result</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Risk Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.findings.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="py-10 text-center text-muted-foreground italic">
                    No CORS findings recorded.
                  </TableCell>
                </TableRow>
              ) : (
                data.findings.map((finding, idx) => (
                  <TableRow key={idx} className={cn("group hover:bg-muted/20", finding.status === 'high' && "bg-destructive/5")}>
                    <TableCell className="max-w-[250px]">
                      <div className="font-code text-xs truncate" title={finding.url}>
                        {finding.url}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-[10px] font-code bg-secondary px-1.5 py-0.5 rounded">{finding.origin_tested}</span>
                    </TableCell>
                    <TableCell>
                      <div className="font-code text-[10px] text-muted-foreground">
                        {finding.acao || <span className="opacity-30 italic">None</span>}
                        {finding.acac === 'true' && <span className="ml-2 text-primary font-bold">(With Creds)</span>}
                      </div>
                    </TableCell>
                    <TableCell>{getStatusBadge(finding)}</TableCell>
                    <TableCell className="text-right">
                      <div className={cn("text-[11px] leading-tight", getSeverityColor(finding.severity))}>
                        {finding.issue}
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
      {data.summary.high_risk > 0 && (
        <div className="p-4 rounded-xl border border-destructive/30 bg-destructive/5 flex gap-4">
          <AlertTriangle className="text-destructive shrink-0" size={24} />
          <div className="space-y-1">
            <h4 className="font-bold text-sm text-destructive uppercase tracking-wide">Critical CORS Vulnerability Detected</h4>
            <p className="text-xs text-muted-foreground leading-relaxed">
              One or more endpoints allow arbitrary origins to access sensitive resources while credentials (cookies/auth headers) are enabled. 
              This can be exploited via Cross-Site Request Forgery (CSRF) or data theft from an attacker-controlled website.
              <strong> Action:</strong> Restrict <code>Access-Control-Allow-Origin</code> to a whitelist of trusted domains and avoid using wildcards with credentials.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
