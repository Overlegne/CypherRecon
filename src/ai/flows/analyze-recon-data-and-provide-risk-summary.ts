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
    .optional()
    .describe('Discovered subdomains.'),
  osintData:
    z.array(z.object({
      label: z.string(),
      description: z.string(),
      url: z.string().optional()
    })).optional().describe('Open Source Intelligence (OSINT) findings, e.g., exposed emails, employee names, social media links.'),
  certificateTransparency:
    z.array(z.string()).optional().describe('Information from Certificate Transparency logs, e.g., unusual certificate entries.'),
  portScanResults:
    z.array(
      z.object({
        port: z.number(),
        service: z.string(),
        version: z.string().optional(),
        state: z.string(), // e.g., 'open', 'closed', 'filtered'
      })
    )
    .optional()
    .describe(
      'Results from port and service scans, including open ports, services, and versions.'
    ),
  techStack:
    z.array(z.string()).optional().describe('Detected technologies and frameworks used by the target application/API.'),
  apiEndpoints: z.array(z.string()).optional().describe('Discovered API endpoints.'),
  screenshots:
    z.array(z.string()).optional().describe('URLs or descriptions of screenshots taken from the target application.'),
});
export type AnalyzeReconDataAndProvideRiskSummaryInput = z.infer<
  typeof AnalyzeReconDataAndProvideRiskSummaryInputSchema
>;

// Output Schema
const AnalyzeReconDataAndProvideRiskSummaryOutputSchema = z.object({
  riskSummary:
    z.string().describe('A concise summary of potential risks and vulnerabilities identified from the reconnaissance data.'),
  riskScore:
    z.number().min(0).max(100).describe('A preliminary risk score from 0 (no risk) to 100 (critical risk).'),
  riskExplanation:
    z.string().describe('An explanation detailing the reasoning behind the assigned risk score and highlighting key contributing factors.'),
  potentialVulnerabilities:
    z.array(
      z.object({
        type:
          z.string().describe('The type of potential vulnerability (e.g., "Exposed Information", "Outdated Software", "Weak Configuration").'),
        description:
          z.string().describe('A brief description of the potential vulnerability.'),
        severity:
          z.enum(['Low', 'Medium', 'High', 'Critical']).describe('The severity of the potential vulnerability.'),
        recommendation:
          z.string().optional().describe('A brief recommendation for addressing the vulnerability.'),
      })
    )
    .optional()
    .describe(
      'A list of specific potential vulnerabilities identified, with type, description, and severity.'
    ),
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
  prompt: `You are an expert ethical hacker and cybersecurity analyst. Your task is to analyze the provided reconnaissance data for a given target and identify potential risks and vulnerabilities. Based on your analysis, generate a concise summary, assign a preliminary risk score (0-100), explain the score, and list specific potential vulnerabilities.\n\nTarget: {{{target}}}\n\nReconnaissance Data:\n\n{{#if subdomains}}\nSubdomains:\n{{#each subdomains}}- {{{this}}}\n{{/each}}\n{{/if}}\n\n{{#if osintData}}\nOSINT Data:\n{{#each osintData}}- {{this.label}}: {{this.description}}{{#if this.url}} (Link: {{this.url}}){{/if}}\n{{/each}}\n{{/if}}\n\n{{#if certificateTransparency}}\nCertificate Transparency Data:\n{{#each certificateTransparency}}- {{{this}}}\n{{/each}}\n{{/if}}\n\n{{#if portScanResults}}\nPort Scan Results:\n{{#each portScanResults}}- Port: {{this.port}}, Service: {{this.service}}{{#if this.version}}, Version: {{this.version}}{{/if}}, State: {{this.state}}\n{{/each}}\n{{/if}}\n\n{{#if techStack}}\nTechnology Stack:\n{{#each techStack}}- {{{this}}}\n{{/each}}\n{{/if}}\n\n{{#if apiEndpoints}}\nAPI Endpoints:\n{{#each apiEndpoints}}- {{{this}}}\n{{/each}}\n{{/if}}\n\n{{#if screenshots}}\nScreenshots (descriptions/URLs):\n{{#each screenshots}}- {{{this}}}\n{{/each}}\n{{/if}}\n\nInstructions:\n1.  Provide a 'riskSummary' that concisely highlights the most significant potential risks and vulnerabilities.\n2.  Assign a 'riskScore' between 0 and 100, where 0 means no significant risk and 100 means critical, immediate attention required.\n3.  Provide a 'riskExplanation' justifying the 'riskScore' based on the analyzed data.\n4.  List 'potentialVulnerabilities' as an array of objects, each with 'type', 'description', 'severity' (Low, Medium, High, Critical), and optionally 'recommendation'. Focus on concrete, actionable findings.\n`,
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
