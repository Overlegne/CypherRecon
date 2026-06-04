# CypherRecon

CypherRecon is a modern, AI-powered ethical hacking reconnaissance dashboard. It provides a visual interface for managing target sequences, monitoring real-time scan telemetry, and performing automated risk assessments using Google Gemini.

## Features

- **Dynamic Pipeline Configuration**: Choose which modules (Subdomains, OSINT, Port Scanning, etc.) to run for every target.
- **Deep Network Discovery**: Full port scanning simulations and service fingerprinting.
- **Visual Attack Surface**: Automated screenshotting and visual snapshot gallery.
- **AI-Powered Risk Analysis**: Integrated Genkit flows that analyze scan results to provide risk scores and vulnerability summaries.
- **External Backend Support**: Fully decoupled architecture ready to connect to your local Python/Go scanner service.
- **Persistent Settings**: Local storage for API keys (Shodan, VirusTotal, etc.) and global scanning preferences.

## Getting Started

### 1. Frontend Setup
This is a Next.js application. Ensure you have Node.js installed.
The dashboard will run on `http://localhost:9002` by default.

### 2. Local Backend Integration
CypherRecon is designed to be a thin client. You must provide a local backend (e.g., using FastAPI or Flask) at the URL configured in the **Settings** menu (default: `http://localhost:5000`).

#### Expected API Endpoints:
- `GET /targets`: Returns an array of `Target` objects.
- `POST /targets`: Creates a new target entry.
- `DELETE /targets/:id`: Removes a target.
- `GET /targets/:id`: Returns status, progress, and results for a target.
- `POST /targets/:id/scan`: Initiates the scanning process on your local machine.
- `POST /targets/:id/risk`: Stores the AI-generated risk assessment.

### 3. Environment Variables
To enable the AI risk assessment, ensure you have a `GEMINI_API_KEY` in your `.env` file for Genkit.

## Technical Stack
- **Framework**: Next.js 15 (App Router)
- **Styling**: Tailwind CSS & ShadCN UI
- **AI Logic**: Genkit v1.x (Google Generative AI)
- **Icons**: Lucide React
- **Charts**: Recharts

## License
Ethical Use Only. Built for educational and professional security research purposes.