"use client";

import { AnalyzeReconDataAndProvideRiskSummaryOutput } from '@/ai/flows/analyze-recon-data-and-provide-risk-summary';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './ui/card';
import { Progress } from './ui/progress';
import { Badge } from './ui/badge';
import { AlertCircle, ShieldAlert, CheckCircle2, ChevronRight } from 'lucide-react';

export function RiskAnalysisView({ data }: { data: AnalyzeReconDataAndProvideRiskSummaryOutput }) {
  const getScoreColor = (score: number) => {
    if (score < 30) return 'text-green-400';
    if (score < 60) return 'text-yellow-400';
    return 'text-red-500';
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return <Badge variant="destructive">Critical</Badge>;
      case 'high': return <Badge className="bg-orange-500 hover:bg-orange-600">High</Badge>;
      case 'medium': return <Badge className="bg-yellow-500 hover:bg-yellow-600">Medium</Badge>;
      default: return <Badge variant="secondary">Low</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card className="col-span-1 border-primary/20 bg-primary/5">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Threat Score</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center pt-2">
            <span className={`text-6xl font-bold font-code mb-4 ${getScoreColor(data.riskScore)}`}>
              {data.riskScore}
            </span>
            <Progress value={data.riskScore} className="h-2 w-full mb-2" />
            <p className="text-xs text-muted-foreground text-center">Preliminary AI assessment based on reconnaissance findings.</p>
          </CardContent>
        </Card>

        <Card className="col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium uppercase tracking-wider text-muted-foreground">Risk Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-relaxed mb-4">{data.riskSummary}</p>
            <div className="bg-secondary/50 rounded-lg p-4 border border-border">
              <h4 className="text-xs font-semibold uppercase mb-2 flex items-center gap-2">
                <AlertCircle size={14} className="text-primary" />
                Strategic Explanation
              </h4>
              <p className="text-xs text-muted-foreground leading-relaxed">{data.riskExplanation}</p>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-4">
        <h3 className="text-lg font-semibold flex items-center gap-2">
          <ShieldAlert size={20} className="text-accent" />
          Potential Vulnerabilities
        </h3>
        <div className="grid grid-cols-1 gap-3">
          {data.potentialVulnerabilities?.map((vuln, idx) => (
            <div key={idx} className="group p-4 rounded-xl border border-border bg-card hover:border-primary/40 transition-all">
              <div className="flex items-start justify-between mb-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-3">
                    {getSeverityBadge(vuln.severity)}
                    <span className="font-semibold text-base">{vuln.type}</span>
                  </div>
                  <p className="text-sm text-muted-foreground">{vuln.description}</p>
                </div>
              </div>
              {vuln.recommendation && (
                <div className="mt-3 pl-4 border-l-2 border-primary/20 bg-primary/5 p-3 rounded-r-lg">
                  <div className="flex items-center gap-2 text-xs font-medium text-primary mb-1">
                    <CheckCircle2 size={12} />
                    Remediation Path
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{vuln.recommendation}</p>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}