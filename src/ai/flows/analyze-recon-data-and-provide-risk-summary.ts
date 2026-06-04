'use server';
/**
 * @fileOverview A Genkit flow for analyzing reconnaissance data and providing a risk summary and score.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

// Input Schema
const AnalyzeReconDataAndProvideRiskSummaryInputSchema = z.object({
  target: z.string().describe('The primary target domain or IP address.'),
  subdomains: z.array(z.string()).nullable().optional(),
  osintData: z.array(z.any()).nullable().optional(),
  portScanResults: z.array(z.any()).nullable().optional(),
  webSurface: z.any().nullable().optional(),
  tlsData: z.any().nullable().optional(),
  urlHarvesting: z.object({
    urls: z.array(z.object({
      url: z.string(),
      type: z.string(),
      interesting: z.boolean()
    })),
    summary: z.any()
  }).nullable().optional(),
  cors_audit: z.any().nullable().optional(),
  techStack: z.array(z.string()).nullable().optional(),
  apiEndpoints: z.array(z.string()).nullable().optional(),
  screenshots: z.array(z.string()).nullable().optional(),
});
export type AnalyzeReconDataAndProvideRiskSummaryInput = z.infer<
  typeof AnalyzeReconDataAndProvideRiskSummaryInputSchema
>;

// Output Schema
const AnalyzeReconDataAndProvideRiskSummaryOutputSchema = z.object({
  riskSummary: z.string(),
  riskScore: z.number().min(0).max(100),
  riskExplanation: z.string(),
  potentialVulnerabilities: z.array(
    z.object({
      type: z.string(),
      description: z.string(),
      severity: z.enum(['Low', 'Medium', 'High', 'Critical']),
      recommendation: z.string().optional(),
    })
  ).optional(),
});
export type AnalyzeReconDataAndProvideRiskSummaryOutput = z.infer<
  typeof AnalyzeReconDataAndProvideRiskSummaryOutputSchema
>;

export async function analyzeReconDataAndProvideRiskSummary(
  input: AnalyzeReconDataAndProvideRiskSummaryInput
): Promise<AnalyzeReconDataAndProvideRiskSummaryOutput> {
  return analyzeReconDataAndProvideRiskSummaryFlow(input);
}

const analyzeReconDataAndProvideRiskSummaryPrompt = ai.definePrompt({
  name: 'analyzeReconDataAndProvideRiskSummaryPrompt',
  input: {schema: AnalyzeReconDataAndProvideRiskSummaryInputSchema},
  output: {schema: AnalyzeReconDataAndProvideRiskSummaryOutputSchema},
  prompt: `Analyze this reconnaissance data for target: {{{target}}}

{{#if urlHarvesting}}
Harvested URLs:
- Total: {{urlHarvesting.summary.found}}
- API Endpoints found: {{urlHarvesting.summary.api_endpoints}}
- Interesting paths: {{#each urlHarvesting.urls}}{{#if this.interesting}}{{{this.url}}} (Type: {{this.type}}), {{/if}}{{/each}}
{{/if}}

{{#if webSurface}}
Web Surface: 
- Tested: {{webSurface.summary.tested}}
- OK: {{webSurface.summary.ok}}
- Missing: {{webSurface.summary.missing}}
- Weak: {{webSurface.summary.weak}}
{{/if}}

{{#if tlsData}}
TLS Analysis:
- Supported: {{tlsData.summary.supported_versions}}
- Insecure: {{tlsData.summary.insecure_versions}}
- Weak Ciphers: {{tlsData.summary.weak_ciphers}}
{{/if}}

{{#if cors_audit}}
CORS Audit: 
- Tested Endpoints: {{cors_audit.summary.tested_endpoints}}
- High Risk Findings: {{cors_audit.summary.high_risk}}
{{/if}}

Identify significant risks. Focus on exposed admin panels, sensitive backup files, unprotected API endpoints, and CORS misconfigurations.
Provide a risk score 0-100 and a list of potential vulnerabilities with recommendations.`,
});

const analyzeReconDataAndProvideRiskSummaryFlow = ai.defineFlow(
  {
    name: 'analyzeReconDataAndProvideRiskSummaryFlow',
    inputSchema: AnalyzeReconDataAndProvideRiskSummaryInputSchema,
    outputSchema: AnalyzeReconDataAndProvideRiskSummaryOutputSchema,
  },
  async input => {
    const {output} = await analyzeReconDataAndProvideRiskSummaryPrompt(input);
    return output!;
  }
);
