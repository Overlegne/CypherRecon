"use client";

import { TLSData } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';
import { ShieldCheck, ShieldAlert, AlertCircle, Lock, Unlock, Globe, Terminal } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';

export function TLSAnalysisView({ data }: { data: TLSData }) {
  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'high': return <Badge variant="destructive">Insecure</Badge>;
      case 'medium': return <Badge className="bg-yellow-500 text-black">Weak</Badge>;
      case 'low': return <Badge className="bg-green-500">Secure</Badge>;
      default: return <Badge variant="outline">N/A</Badge>;
    }
  };

  const getCipherBadge = (status: string) => {
    switch (status) {
      case 'ok': return <Badge className="bg-green-500/20 text-green-400 border-green-500/30">Secure</Badge>;
      case 'weak': return <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">Weak</Badge>;
      case 'insecure': return <Badge className="bg-red-500/20 text-red-400 border-red-500/30">Insecure</Badge>;
      default: return null;
    }
  };

  // Define expected protocols to show completeness
  const ALL_VERSIONS = ["SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-secondary/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code">{data.summary.supported_versions}</span>
            <span className="text-xs text-muted-foreground uppercase">Protocols Supported</span>
          </CardContent>
        </Card>
        <Card className={data.summary.insecure_versions > 0 ? "bg-red-500/5 border-red-500/20" : "bg-green-500/5 border-green-500/20"}>
          <CardContent className="pt-6 text-center">
            <span className={`block text-3xl font-bold font-code ${data.summary.insecure_versions > 0 ? 'text-red-500' : 'text-green-500'}`}>
              {data.summary.insecure_versions}
            </span>
            <span className="text-xs text-muted-foreground uppercase">Insecure Protocols</span>
          </CardContent>
        </Card>
        <Card className={data.summary.weak_ciphers > 0 ? "bg-yellow-500/5 border-yellow-500/20" : "bg-secondary/20"}>
          <CardContent className="pt-6 text-center">
            <span className={`block text-3xl font-bold font-code ${data.summary.weak_ciphers > 0 ? 'text-yellow-500' : ''}`}>
              {data.summary.weak_ciphers}
            </span>
            <span className="text-xs text-muted-foreground uppercase">Weak Ciphers</span>
          </CardContent>
        </Card>
        <Card className={data.summary.insecure_ciphers > 0 ? "bg-red-500/5 border-red-500/20" : "bg-secondary/20"}>
          <CardContent className="pt-6 text-center">
            <span className={`block text-3xl font-bold font-code ${data.summary.insecure_ciphers > 0 ? 'text-red-500' : ''}`}>
              {data.summary.insecure_ciphers}
            </span>
            <span className="text-xs text-muted-foreground uppercase">Insecure Ciphers</span>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Globe size={18} className="text-primary" />
              Protocol Support Matrix
            </CardTitle>
            <CardDescription>Status of various SSL/TLS versions on this target.</CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Version</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Negotiated Cipher</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ALL_VERSIONS.map((version) => {
                  const v = data.versions.find(dv => dv.version === version);
                  return (
                    <TableRow key={version}>
                      <TableCell className="font-bold">{version}</TableCell>
                      <TableCell>
                        {v?.supported ? (
                          <div className="flex items-center gap-2">
                            <Lock size={14} className={v.severity === 'high' ? "text-red-500" : v.severity === 'medium' ? "text-yellow-500" : "text-green-500"} />
                            {getSeverityBadge(v.severity)}
                          </div>
                        ) : (
                          <div className="flex items-center gap-2 text-muted-foreground">
                            <Unlock size={14} />
                            <span className="text-xs">Not Supported</span>
                          </div>
                        )}
                      </TableCell>
                      <TableCell className="font-code text-[10px] text-muted-foreground">
                        {v?.cipher || '-'}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Terminal size={18} className="text-accent" />
              Detailed Cipher Findings
            </CardTitle>
            <CardDescription>Cryptographic algorithms identified during handshakes.</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {data.ciphers.length > 0 ? data.ciphers.map((c, idx) => (
                <div key={idx} className="flex items-center justify-between p-3 rounded-lg border border-border bg-secondary/10">
                  <span className="font-code text-xs truncate max-w-[250px]" title={c.name}>{c.name}</span>
                  {getCipherBadge(c.status)}
                </div>
              )) : (
                <div className="py-10 text-center text-muted-foreground italic text-sm">
                  No specific cipher suites identified.
                </div>
              )}
            </div>
            {data.summary.insecure_versions > 0 && (
              <div className="mt-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex gap-3">
                <AlertCircle className="text-red-500 shrink-0 mt-1" size={18} />
                <div className="space-y-1">
                  <h4 className="font-bold text-sm text-red-500">Security Warning</h4>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    This target supports legacy TLS/SSL versions. This could allow for downgrade attacks (e.g., POODLE). It is highly recommended to disable TLS 1.0 and 1.1.
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
