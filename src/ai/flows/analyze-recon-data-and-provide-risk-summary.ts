'use server';
/**
 * @fileOverview A Genkit flow for analyzing reconnaissance data and providing a risk summary and score.
 *
 * - analyzeReconDataAndProvideRiskSummary - A function that analyzes gathered reconnaissance data and provides a risk summary and score.
 * - AnalyzeReconDataAndProvideRiskSummaryInput - The input type for the analyzeReconDataAndProvideRiskSummary function.
 * - AnalyzeReconDataAndProvideRiskSummaryOutput - The return type for the analyzeReconDataAndProvideRiskSummary function.
 */

import {ai} from '@/ai/genkit';
import {z} from 'genkit';

// Input Schema
const AnalyzeReconDataAndProvideRiskSummaryInputSchema = z.object({
  target: z.string().describe('The primary target domain or IP address.'),
  subdomains: z
    .array(z.string())
    .nullable()
    .optional()
    .describe('Discovered subdomains.'),
  osintData:
    z.array(z.object({
      label: z.string(),
      description: z.string(),
      url: z.string().optional(),
      type: z.string()
    }))
    .nullable()
    .optional().describe('Open Source Intelligence (OSINT) findings.'),
  portScanResults:
    z.array(
      z.object({
        port: z.number(),
        service: z.string(),
        version: z.string().optional(),
        state: z.string(),
      })
    )
    .nullable()
    .optional()
    .describe('Results from port and service scans.'),
  techStack:
    z.array(z.string())
    .nullable()
    .optional().describe('Detected technologies.'),
  webSurface: z.object({
    summary: z.object({
      tested: z.number(),
      ok: z.number(),
      missing: z.number(),
      weak: z.number()
    }),
    headers: z.array(z.object({
      name: z.string(),
      status: z.string(),
      severity: z.string()
    }))
  })
  .nullable()
  .optional().describe('Security header analysis results.'),
  tlsData: z.object({
    versions: z.array(z.object({
      version: z.string(),
      supported: z.boolean(),
      severity: z.string()
    })),
    summary: z.object({
      insecure_versions: z.number(),
      weak_ciphers: z.number()
    })
  })
  .nullable()
  .optional().describe('SSL/TLS analysis results.'),
  apiEndpoints: z.array(z.string())
  .nullable()
  .optional().describe('Discovered API endpoints.'),
  screenshots:
    z.array(z.string())
    .nullable()
    .optional().describe('URLs or descriptions of screenshots.'),
});
export type AnalyzeReconDataAndProvideRiskSummaryInput = z.infer<
  typeof AnalyzeReconDataAndProvideRiskSummaryInputSchema
>;

// Output Schema
const AnalyzeReconDataAndProvideRiskSummaryOutputSchema = z.object({
  riskSummary:
    z.string().describe('A concise summary of potential risks and vulnerabilities.'),
  riskScore:
    z.number().min(0).max(100).describe('A preliminary risk score from 0 to 100.'),
  riskExplanation:
    z.string().describe('An explanation detailing the reasoning behind the assigned risk score.'),
  potentialVulnerabilities:
    z.array(
      z.object({
        type:
          z.string().describe('The type of potential vulnerability.'),
        description:
          z.string().describe('A brief description.'),
        severity:
          z.enum(['Low', 'Medium', 'High', 'Critical']).describe('The severity.'),
        recommendation:
          z.string().optional().describe('A brief recommendation.'),
      })
    )
    .optional()
    .describe('A list of specific potential vulnerabilities identified.'),
});
export type AnalyzeReconDataAndProvideRiskSummaryOutput = z.infer<
  typeof AnalyzeReconDataAndProvideRiskSummaryOutputSchema
>;

// Wrapper function
export async function analyzeReconDataAndProvideRiskSummary(
  input: AnalyzeReconDataAndProvideRiskSummaryInput
): Promise<AnalyzeReconDataAndProvideRiskSummaryOutput> {
  return analyzeReconDataAndProvideRiskSummaryFlow(input);
}

// Prompt definition
const analyzeReconDataAndProvideRiskSummaryPrompt = ai.definePrompt({
  name: 'analyzeReconDataAndProvideRiskSummaryPrompt',
  input: {schema: AnalyzeReconDataAndProvideRiskSummaryInputSchema},
  output: {schema: AnalyzeReconDataAndProvideRiskSummaryOutputSchema},
  prompt: `You are an expert ethical hacker and cybersecurity analyst. Analyze the provided reconnaissance data for a given target and identify potential risks.

Target: {{{target}}}

Reconnaissance Data:
{{#if subdomains}}Subdomains: {{#each subdomains}}- {{{this}}} {{/each}}{{/if}}
{{#if portScanResults}}Ports: {{#each portScanResults}}- Port: {{this.port}}, Service: {{this.service}}, State: {{this.state}} {{/each}}{{/if}}
{{#if webSurface}}
Web Surface (Security Headers):
- Summary: Tested: {{webSurface.summary.tested}}, OK: {{webSurface.summary.ok}}, Missing: {{webSurface.summary.missing}}, Weak: {{webSurface.summary.weak}}
{{#each webSurface.headers}}
- Header: {{this.name}}, Status: {{this.status}}, Severity: {{this.severity}}
{{/each}}
{{/if}}
{{#if tlsData}}
SSL/TLS Security:
- Insecure Protocols: {{tlsData.summary.insecure_versions}}
- Weak Ciphers: {{tlsData.summary.weak_ciphers}}
{{#each tlsData.versions}}
- {{this.version}}: {{#if this.supported}}Supported (Severity: {{this.severity}}){{else}}Not Supported{{/if}}
{{/each}}
{{/if}}

Instructions:
1. Provide a 'riskSummary' highlighting the most significant risks.
2. Assign a 'riskScore' (0-100).
3. Provide a 'riskExplanation' justifying the score.
4. List 'potentialVulnerabilities' with severity and recommendations. Focus on missing security headers and weak SSL/TLS protocols.`,
});

// Flow definition
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
