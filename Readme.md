# URL Phishing Detector

A local-first phishing URL analysis application using Flask, deterministic URL evidence, URLhaus threat intelligence, and a local Ollama LLM.

## Architecture

```text
Browser
  ↓
Flask API (/api/analyze)
  ↓
AIAnalysisService
  ├─ URL validation + normalization
  ├─ EvidenceBuilder (objective URL facts)
  ├─ URLhaus threat intelligence
  ├─ Ollama / qwen2.5vl:7b
  ├─ AISafetyValidator (objective guardrails)
  └─ AIOutputSanitizer
  ↓
JSON response
  ↓
Frontend
```

## Features

- URL validation and normalization
- Seven objective security checks
- IPv4/IPv6 and hostname analysis
- Suspicious keyword detection
- URL/query/hostname structural indicators
- Optional URLhaus threat intelligence
- Local Ollama analysis using `qwen2.5vl:7b`
- LLM JSON parsing and schema validation
- AI safety guardrails against unsupported conclusions
- Output sanitization
- Flask web UI and JSON API
- Health and feature-status endpoints
- Offline unit tests plus opt-in live integration tests

## Windows setup

The project was developed around Python 3.12 and Ollama on Windows.

```powershell
cd D:\Phishing_link_Detection
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Edit `.env` and add your URLhaus key. Do not commit `.env`.

### Ollama

Make sure Ollama is running and the model exists:

```powershell
ollama serve
ollama pull qwen2.5vl:7b
```

Then start Flask:

```powershell
python server_main.py
```

Open `http://127.0.0.1:5000`.

## API

### Analyze

`POST /api/analyze`

```json
{"url":"https://example.com"}
```

The response contains:

- `verdict`: `safe`, `suspicious`, or `phishing`
- `risk_score`: 0–100
- `safety_score`: `100 - risk_score`
- `confidence`: 0.0–1.0
- `checks`: objective security checks
- `indicators`: AI-generated evidence explanations
- `validation`: safety-validator result
- `evidence`: structured URL facts
- `threat_intelligence`: URLhaus result

### Health

`GET /api/health`

Reports whether the Flask service is running and whether the configured Ollama endpoint currently responds.

### Stats

`GET /api/stats`

Reports enabled application capabilities.

## Testing

Run the offline test suite:

```powershell
python -m pytest -q
```

Live Ollama/URLhaus integration tests are opt-in:

```powershell
$env:RUN_LIVE_AI_TESTS="1"
python -m pytest -q
```

## Security notes

- Never commit `.env` or API keys.
- HTTPS is treated as transport encryption, not proof of legitimacy.
- A URLhaus `no_results` response does not prove a URL is safe.
- IP-address hosting alone does not prove maliciousness.
- The LLM receives structured evidence rather than being asked to invent domain reputation.
