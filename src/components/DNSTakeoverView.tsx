"use client";

import { DNSTakeoverData, DNSRecord } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';
import { ShieldCheck, ShieldAlert, AlertTriangle, Globe, Network, Server, Cloud } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { cn } from '@/lib/utils';

export function DNSTakeoverView({ data }: { data: DNSTakeoverData }) {
  const getStatusBadge = (record: DNSRecord) => {
    switch (record.status) {
      case 'high':
        return <Badge variant="destructive" className="gap-1"><ShieldAlert size={12} /> TAKEOVER RISK</Badge>;
      case 'suspicious':
        return <Badge className="bg-yellow-500 text-black hover:bg-yellow-600 gap-1"><AlertTriangle size={12} /> SUSPICIOUS</Badge>;
      case 'wildcard':
        return <Badge variant="secondary" className="gap-1"><Globe size={12} /> WILDCARD</Badge>;
      case 'ok':
        return <Badge className="bg-green-500 hover:bg-green-600 gap-1"><ShieldCheck size={12} /> SECURE</Badge>;
      default:
        return <Badge variant="outline">UNKNOWN</Badge>;
    }
  };

  const getRecordColor = (type: string) => {
    switch (type) {
      case 'CNAME': return 'text-primary font-bold';
      case 'A': return 'text-green-500';
      case 'TXT': return 'text-yellow-500';
      case 'NS': return 'text-orange-500';
      default: return 'text-muted-foreground';
    }
  };

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-secondary/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code">{data.summary.tested}</span>
            <span className="text-xs text-muted-foreground uppercase">Subdomains Audited</span>
          </CardContent>
        </Card>
        <Card className="bg-primary/5 border-primary/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-primary">{data.summary.cname_records}</span>
            <span className="text-xs text-muted-foreground uppercase">CNAME Records</span>
          </CardContent>
        </Card>
        <Card className="bg-yellow-500/5 border-yellow-500/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code text-yellow-500">{data.summary.suspicious}</span>
            <span className="text-xs text-muted-foreground uppercase">Suspicious</span>
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
            <Network size={18} className="text-primary" />
            DNS Configuration & Takeover Audit
          </CardTitle>
          <CardDescription>
            Live analysis of DNS records to identify dangling resources and hijacking risks.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader className="bg-muted/30">
              <TableRow>
                <TableHead>Subdomain</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Record Value</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Risk Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.records.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="py-10 text-center text-muted-foreground italic">
                    No DNS records analyzed yet.
                  </TableCell>
                </TableRow>
              ) : (
                data.records.map((record, idx) => (
                  <TableRow key={idx} className={cn("group hover:bg-muted/20", record.status === 'high' && "bg-destructive/5")}>
                    <TableCell>
                      <div className="font-bold text-sm">{record.subdomain}</div>
                    </TableCell>
                    <TableCell>
                      <span className={cn("text-xs px-1.5 py-0.5 rounded bg-secondary", getRecordColor(record.type))}>
                        {record.type}
                      </span>
                    </TableCell>
                    <TableCell className="max-w-[300px]">
                      <div className="font-code text-[11px] truncate text-muted-foreground" title={record.value}>
                        {record.value}
                      </div>
                    </TableCell>
                    <TableCell>{getStatusBadge(record)}</TableCell>
                    <TableCell className="text-right">
                      <div className={cn("text-[11px] leading-tight max-w-[200px] ml-auto", 
                        record.status === 'high' ? "text-red-500 font-bold" : "text-yellow-500"
                      )}>
                        {record.issue || "-"}
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
          <Cloud className="text-destructive shrink-0" size={24} />
          <div className="space-y-1">
            <h4 className="font-bold text-sm text-destructive uppercase tracking-wide">Critical DNS Takeover Risk</h4>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Een of meer subdomeinen verwijzen via CNAME naar een externe service (SaaS/Cloud) die niet langer geconfigureerd lijkt te zijn. 
              Aanvallers kunnen dit record registreren bij de provider en zo het subdomein overnemen voor phishing of data-exfiltratie.
              <strong> Actie:</strong> Verwijder dangling CNAME-records onmiddellijk of claim het domein bij de provider.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
