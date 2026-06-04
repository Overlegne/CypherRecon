# **App Name**: CypherRecon

## Core Features:

- Target & Mode Management: Gebruikers kunnen pentest-doelen (domeinen/IP's) definiëren, de blackbox of greybox testmodus specificeren en de scanstatus volgen.
- Customizable Recon Modules: In- of uitschakelen van specifieke reconnaissance-modules (bijv. subdomain-enumeratie, poortscanning, detectie van tech-stack) voor elk doel.
- Automated Recon Workflow Engine: Voert de geconfigureerde reconnaissance-modules sequentieel uit, inclusief subdomain-enumeratie, OSINT, certificate transparency checks, poort-/service-scans, tech-stack detectie en API-endpoint-discovery.
- AI-Powered Risk Assessment Tool: Analyseert de verzamelde reconnaissance-gegevens om een voorlopige risicoscore te geven voor geïdentificeerde kwetsbaarheden of verkeerde configuraties.
- Real-time Scan Progress & Logging: Bekijk live statusupdates, voortgang in procenten per doel, de actieve module en uitvoerlogboeken in een speciale gebruikersinterface.
- Comprehensive Reporting & Export: Genereert gedetailleerde HTML-rapporten voor een overzicht en ruwe uitvoer in JSON- en Markdown-formaten voor eenvoudige integratie en beoordeling.

## Style Guidelines:

- Dark scheme. Primary color: Deep electric blue (#1963F2) to convey a sense of professionalism and cutting-edge technology, fitting for a cybersecurity tool. Background color: Very dark charcoal blue (#15181F), creating a focused, low-light environment similar to a hacker's terminal. Accent color: Vibrant purple (#8F24F7) for interactive elements and highlights, providing contrast and a futuristic feel without being distracting.
- Body and headline font: 'Inter' (sans-serif) for its modern, clear, and highly readable quality, suitable for detailed technical information. Code and log text font: 'Source Code Pro' (monospace sans-serif) to perfectly render code snippets, console output, and raw data, maintaining alignment and readability typical of development environments.
- Utilize minimalistic, sharp geometric icons. Emphasize iconography that visually represents cybersecurity concepts like network, lock, scan, and data. Maintain a consistent monochrome style or a dual-tone approach using the primary blue and purple for interactive states.
- A dashboard-centric layout with a clean left-sidebar for target selection and module navigation, and a spacious main content area for detailed views of reconnaissance results, real-time logs, and report generation. Employ cards and tabbed interfaces to organize complex information efficiently and prevent visual clutter, crucial for data-heavy analysis.
- Subtle, functional animations to indicate activity and progress, such as loading spinners for modules, animated progress bars for ongoing scans, and smooth transitions for section expansions or view changes. Animations should be swift and unobtrusive, designed to inform rather than distract.