
"use client";

import { WebSurfaceData, WebHeader } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';
import { ShieldCheck, AlertCircle, Info, ExternalLink, ShieldAlert, Globe } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

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

  return (
    <div className="space-y-6">
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

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-lg flex items-center gap-2">
            <Globe size={18} className="text-primary" />
            Security Headers Analysis
          </CardTitle>
          <CardDescription>
            Target URLs: {data.urls_tested.join(', ')}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Security Header</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Risk Level</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.headers.map((header, idx) => (
                <TableRow key={idx} className="group">
                  <TableCell className="font-medium">{header.name}</TableCell>
                  <TableCell>{getStatusBadge(header.status)}</TableCell>
                  <TableCell className="max-w-[300px]">
                    <div className="font-code text-xs truncate" title={header.value || ''}>
                      {header.value || <span className="italic opacity-50">Not Set</span>}
                    </div>
                  </TableCell>
                  <TableCell>
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

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {data.headers.filter(h => h.status !== 'ok' && h.status !== 'info').map((h, i) => (
          <div key={i} className="p-4 rounded-xl border border-border bg-card/50 flex gap-4">
            <div className={`mt-1 ${getSeverityColor(h.severity)}`}>
              <ShieldAlert size={20} />
            </div>
            <div className="space-y-1">
              <h4 className="font-bold text-sm">{h.name} is {h.status}</h4>
              <p className="text-xs text-muted-foreground leading-relaxed">
                {h.recommendation || 'This security header is essential for protecting the application from common web attacks.'}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
