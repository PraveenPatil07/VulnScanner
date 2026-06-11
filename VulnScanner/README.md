# Code Vulnerability Scanner

A production-grade code vulnerability scanner with a Python/FastAPI backend and React/TypeScript frontend. Uses regex + AST-based static analysis (zero LLM) for detection, with optional Claude AI-powered report generation via streaming SSE.

## Features

- **26 vulnerability categories** across 10+ programming languages
- **Static analysis engine** using regex patterns + Python AST (no LLM required for scanning)
- **AI-powered reports** via Claude Sonnet streaming
- **SARIF 2.1.0 export** for IDE integration
- **Framework mapping** to MITRE ATT&CK, NIST CSF, OWASP Top 10
- **Real-time progress** via Server-Sent Events
- **Dark mode UI** with severity dashboards and charts

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 20+
- Docker & Docker Compose (optional)

### Local Development

1. **Clone and install:**
   ```bash
   # Backend
   cd backend
   pip install -r requirements.txt
   cp .env.example .env
   # Edit .env with your ANTHROPIC_API_KEY

   # Frontend
   cd frontend
   npm install
   ```

2. **Start backend:**
   ```bash
   cd backend
   uvicorn main:app --reload --port 8000
   ```

3. **Start frontend:**
   ```bash
   cd frontend
   npm run dev
   ```

4. Open http://localhost:5173

### Docker

```bash
cp .env.example backend/.env
# Edit backend/.env with your ANTHROPIC_API_KEY
docker compose up --build
```

Frontend: http://localhost:3000  
Backend API: http://localhost:8000/api/health

## Architecture

```
User Input (React) → Ingest (ZIP/HLD) → Static Scan Engine → LLM Report → Output (UI/JSON/SARIF)
```

### Backend Structure

```
backend/
├── api/            # FastAPI routes & middleware
├── llm/            # Anthropic Claude integration
├── models/         # Pydantic models (Finding, ScanResult, SARIF)
├── rules/          # YAML vulnerability rules by language
├── scanner/        # Core engine (zip_extractor, rule_engine, ast_analyzers)
├── skills/         # Skill metadata (CWE, CVSS, MITRE mappings)
└── tests/          # Pytest test suite
```

### Frontend Structure

```
frontend/src/
├── api/            # Axios client & TypeScript types
├── components/     # React components (FileUpload, FindingCard, etc.)
├── hooks/          # Custom hooks (useScan, useSSE)
├── store/          # Zustand state management
└── utils/          # Severity helpers, formatters
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/scan/upload` | Upload ZIP for scanning |
| GET | `/api/scan/{id}` | Get scan results |
| GET | `/api/scan/{id}/stream` | SSE progress stream |
| GET | `/api/scan/{id}/sarif` | SARIF export |
| GET | `/api/health` | Health check |

## Supported Languages

Python, JavaScript/TypeScript, Java, PHP, Go, Ruby, C#, and universal patterns (secrets, misconfigurations)

## Testing

```bash
cd backend
pytest -v
```

## License

MIT
