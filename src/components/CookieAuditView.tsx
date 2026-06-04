"use client";

import { CookieAuditData, CookieFinding } from '@/lib/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Badge } from './ui/badge';
import { ShieldCheck, ShieldAlert, AlertTriangle, Cookie, Lock, Unlock, Globe } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from './ui/table';
import { cn } from '@/lib/utils';

export function CookieAuditView({ data }: { data: CookieAuditData }) {
  const getStatusBadge = (finding: CookieFinding) => {
    switch (finding.status) {
      case 'high':
        return <Badge variant="destructive" className="gap-1"><ShieldAlert size={12} /> HIGH RISK</Badge>;
      case 'weak':
        return <Badge className="bg-yellow-500 text-black hover:bg-yellow-600 gap-1"><Unlock size={12} /> WEAK</Badge>;
      case 'ok':
        return <Badge className="bg-green-500 hover:bg-green-600 gap-1"><ShieldCheck size={12} /> SECURE</Badge>;
      default:
        return <Badge variant="outline">UNKNOWN</Badge>;
    }
  };

  const getAttributeBadge = (active: boolean, label: string) => {
    return (
      <Badge 
        variant={active ? "default" : "outline"} 
        className={cn(
          "text-[10px] font-bold px-1.5 py-0",
          active ? "bg-green-500/20 text-green-400 border-green-500/30" : "opacity-40"
        )}
      >
        {label}
      </Badge>
    );
  };

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-secondary/20">
          <CardContent className="pt-6 text-center">
            <span className="block text-3xl font-bold font-code">{data.summary.cookies_found}</span>
            <span className="text-xs text-muted-foreground uppercase">Cookies Found</span>
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
            <span className="block text-3xl font-bold font-code text-yellow-500">{data.summary.weak}</span>
            <span className="text-xs text-muted-foreground uppercase">Weak</span>
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
            <Cookie size={18} className="text-primary" />
            Cookie Security Policy Audit
          </CardTitle>
          <CardDescription>
            Analysis of Set-Cookie attributes across tested endpoints.
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader className="bg-muted/30">
              <TableRow>
                <TableHead>Cookie Name</TableHead>
                <TableHead>Attributes</TableHead>
                <TableHead>SameSite</TableHead>
                <TableHead>Domain/Path</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Risk Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.cookies.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="py-10 text-center text-muted-foreground italic">
                    No cookies recorded during scan.
                  </TableCell>
                </TableRow>
              ) : (
                data.cookies.map((cookie, idx) => (
                  <TableRow key={idx} className={cn("group hover:bg-muted/20", cookie.status === 'high' && "bg-destructive/5")}>
                    <TableCell>
                      <div className="font-bold text-sm">{cookie.name}</div>
                      <div className="text-[10px] text-muted-foreground truncate max-w-[150px] font-code">
                        {cookie.value_preview}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        {getAttributeBadge(cookie.httponly, "HttpOnly")}
                        {getAttributeBadge(cookie.secure, "Secure")}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-[10px]">
                        {cookie.samesite || "Not set"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="text-[10px] font-code">
                        <span className="text-muted-foreground">D:</span> {cookie.domain || "Host-only"}<br/>
                        <span className="text-muted-foreground">P:</span> {cookie.path || "/"}
                      </div>
                    </TableCell>
                    <TableCell>{getStatusBadge(cookie)}</TableCell>
                    <TableCell className="text-right">
                      <div className={cn("text-[11px] leading-tight max-w-[200px] ml-auto", 
                        cookie.status === 'high' ? "text-red-500" : "text-yellow-500"
                      )}>
                        {cookie.issue || "-"}
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
            <h4 className="font-bold text-sm text-destructive uppercase tracking-wide">Critical Cookie Vulnerabilities</h4>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Sessie- of authenticatiecookies zonder de <code>HttpOnly</code> of <code>Secure</code> flags zijn kwetsbaar voor diefstal via XSS of sniffing op onbeveiligde verbindingen.
              <strong> Actie:</strong> Forceer altijd <code>Secure; HttpOnly; SameSite=Lax</code> (of Strict) voor alle gevoelige cookies.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
