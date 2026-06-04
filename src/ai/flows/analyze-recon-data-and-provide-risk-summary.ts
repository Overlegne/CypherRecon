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
  webSurface: z.object({
    summary: z.any(),
    headers: z.array(z.any()),
    technology_inventory: z.object({
      technologies: z.array(z.any()),
      summary: z.any()
    }).nullable().optional()
  }).nullable().optional(),
  tlsData: z.any().nullable().optional(),
  urlHarvesting: z.object({
    urls: z.array(z.object({
      url: z.string(),
      type: z.string(),
      interesting: z.boolean()
    })),
    summary: z.any()
  }).nullable().optional(),
  js_inventory: z.object({
    libraries: z.array(z.any()),
    summary: z.any()
  }).nullable().optional(),
  cors_audit: z.any().nullable().optional(),
  cookie_audit: z.any().nullable().optional(),
  dns_takeover: z.any().nullable().optional(),
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

{{#if dns_takeover}}
DNS & Subdomain Takeover Analysis:
- Tested Subdomains: {{dns_takeover.summary.tested}}
- High Risk Takeover Findings: {{dns_takeover.summary.high_risk}}
{{/if}}

{{#if webSurface.technology_inventory}}
Technology Inventory:
- Technologies Found: {{webSurface.technology_inventory.summary.found}}
- Outdated Tech: {{webSurface.technology_inventory.summary.possibly_outdated}}
- High Risk Tech: {{webSurface.technology_inventory.summary.vulnerable_hint}}
- List: {{#each webSurface.technology_inventory.technologies}}{{{this.name}}} v{{this.version}} (Risk: {{{this.risk}}}); {{/each}}
{{/if}}

{{#if js_inventory}}
JavaScript Library Inventory:
- Libraries Found: {{js_inventory.summary.unique_libraries}}
- Outdated/Risky: {{js_inventory.summary.possibly_outdated}}
{{/if}}

{{#if webSurface}}
Web Surface: 
- Tested: {{webSurface.summary.tested}}
- Missing Headers: {{webSurface.summary.missing}}
- Weak Policies: {{webSurface.summary.weak}}
{{/if}}

{{#if tlsData}}
TLS Analysis:
- Supported: {{tlsData.summary.supported_versions}}
- Insecure: {{tlsData.summary.insecure_versions}}
{{/if}}

{{#if cookie_audit}}
Cookie Audit:
- Cookies Found: {{cookie_audit.summary.cookies_found}}
- High Risk Issues: {{cookie_audit.summary.high_risk}}
{{/if}}

Identify significant risks. Focus on outdated server software (webservers, CMS), outdated JavaScript libraries, subdomain takeover, exposed admin panels, and insecure cookies.
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
