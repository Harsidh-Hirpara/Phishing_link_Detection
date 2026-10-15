
from pathlib import Path

readme = r"""# JARVIS — Phishing URL Detection

JARVIS is a Flask-based phishing URL analysis project. It combines URL
heuristics, URLhaus threat-intelligence lookup, local AI analysis using
Ollama/Qwen, optional browser-based observation, behavior analysis, and
forensic reporting.

## Features

- URL normalization and structural analysis.
- Seven security checks displayed in the web interface.
- URLhaus threat-intelligence lookup.
- Local LLM analysis through Ollama using `qwen2.5:3b`.
- Risk-based sandbox triggering (configured threshold: 30).
- Playwright headless Chromium observation when triggered.
- Browser/network event collection and behavior analysis.
- A JARVIS forensic report with the final verdict and risk score.
- Flask JSON API and automated pytest suite.

## Architecture

```text
User submits URL
       |
       v
JARVIS Controller
       |
       v
Pre-scan analysis
  |       |       |
  v       v       v
URLhaus  Heuristics  Qwen via Ollama
       |
       v
Risk assessment
       |
       +---- Risk below threshold ----> Sandbox skipped
       |
       +---- Risk meets threshold ----> Playwright browser
                                             |
                                             v
                                    Event collection
                                             |
                                             v
                                     Behavior analysis
       |                                     |
       +------------------+------------------+
                          v
                  Forensic report
                          |
                          v
                 Verdict and API response
```

## Requirements

- Windows 10/11 or another supported Python environment.
- Python 3.9 or newer (Python 3.10+ is recommended).
- Git, if cloning from a repository.
- Ollama installed locally.
- The Ollama model `qwen2.5:3b`.
- Internet access for URLhaus lookup and any external URL navigation.

## Installation on Windows

Open Command Prompt in the project directory.

### 1. Create and activate the virtual environment

If the project environment already exists, activate it:

```bat
.venv\Scripts\activate
```

To create it from scratch instead:

```bat
python -m venv .venv
.venv\Scripts\activate
```

### 2. Install Python dependencies

```bat
python -m pip install -r requirements.txt
```

Install the Playwright Chromium browser if it is not already installed:

```bat
python -m playwright install chromium
```

### 3. Prepare Ollama

Install Ollama from its official website if necessary:
https://ollama.com/

Download the configured model:

```bat
ollama pull qwen2.5:3b
```

Make sure Ollama is running and the model is available:

```bat
ollama list
```

The application expects Ollama at its configured local endpoint, normally
`http://127.0.0.1:11434`.

If Ollama is not already running as a background application, start it
in a separate terminal:

```bat
ollama serve
```

Keep the Ollama terminal running while using AI analysis.

### 4. Start the Flask application

In the project directory, with the virtual environment active:

```bat
python server_main.py
```

The application uses the `HOST` and `PORT` environment settings when
provided. The default local address is:

http://127.0.0.1:5000/

Open that address in your browser.

## Using the web interface

1. Enter a URL.
2. Click **Analyze** or press Enter.
3. Review the verdict and risk score.
4. Review the seven security checks.
5. When the risk threshold is met, review the sandbox and behavior metrics.
6. Read the forensic report and recommendation.

A low-risk URL may not trigger the browser sandbox. A `safe` verdict
means that strong threat indicators were not detected; it does not
guarantee that a URL is harmless.

## Example test URLs

Safe baseline for UI testing:

```text
https://example.com
```

Reserved-domain test for suspicious URL patterns:

```text
http://secure-login-verify.example.com/account/update?token=12345
```

The second URL is intended to test URL heuristics. It is not evidence
of a real phishing site, and navigation may fail because the hostname
is not registered.

Only test live websites when you have authorization and an appropriate
isolated environment.

## API usage

The analysis endpoint is:

```text
POST http://127.0.0.1:5000/api/analyze
Content-Type: application/json
```

Example request from Windows Command Prompt:

```bat
curl -X POST http://127.0.0.1:5000/api/analyze -H "Content-Type: application/json" -d "{\"url\":\"https://example.com\"}"
```

The JSON response can include:

- `status`, `url`, `verdict`, and `risk_score`
- `checks` and `indicators`
- `threat_intelligence`
- `jarvis.pre_scan`
- `jarvis.sandbox` and `jarvis.behavior` when available
- `jarvis.forensic_report`

Fields related to sandboxing or behavior can be `null` when the sandbox
is not triggered.

## Running tests

Run the full suite:

```bat
python -m pytest -q
```

Run sandbox tests only:

```bat
python -m pytest tests\test_sandbox_service.py -q
```

Run forensic-report tests only:

```bat
python -m pytest tests\test_forensic_reporter.py -q
```

The latest recorded full-suite result during project development was
97 passed. Run the tests again after changing code to verify the current
state.

## Project structure

```text
Phishing_link_Detection/
├── app/
│   ├── features/
│   └── services/
│       ├── behavior_analyzer.py
│       ├── forensic_reporter.py
│       ├── jarvis_controller.py
│       ├── llm_service.py
│       └── sandbox_service.py
├── templates/
│   └── index.html
├── tests/
├── requirements.txt
├── server.py
├── server_main.py
├── QUICKSTART.md
└── Readme.md
```

The exact contents may change as the project evolves.

## Security limitations

- Heuristic and AI analysis can produce false positives and false
  negatives. Do not treat a `safe` verdict as a guarantee.
- URLhaus lookup only indicates whether a listing was found in the
  checked source at the time of the request.
- Headless mode and a separate Playwright browser context do not provide
  OS-level isolation.
- Chromium sandbox configuration depends on the operating system and
  runtime. Before testing untrusted websites, use a dedicated, patched
  virtual machine or similarly isolated environment with restricted
  networking and no access to personal files or credentials.
- Do not expose the development Flask server directly to the public
  internet.
- The project test count is not a measure of phishing-detection accuracy.
  Do not claim a detection-accuracy percentage without a documented,
  representative evaluation dataset and methodology.

## Troubleshooting

### Ollama is unavailable

- Confirm Ollama is running.
- Run `ollama list`.
- Confirm `qwen2.5:3b` is installed.
- Check the configured Ollama endpoint.

### Chromium will not launch

Run:

```bat
python -m playwright install chromium
```

If the issue continues, review the terminal error and use an isolated
supported environment. Do not assume passing unit tests proves that
browser isolation is secure.

### Port 5000 is already in use

Set a different `PORT` value if supported by your configuration, then
restart the application.

### Tests fail

Activate the project's virtual environment, install dependencies, and
run:

```bat
python -m pip install -r requirements.txt
python -m pytest -q
```

## Project status

The application and its automated tests have been exercised locally.
The latest recorded full test run passed 97 tests. This is a development
status, not a security certification or an independently measured
detection-accuracy result.
"""

Path("Readme.md").write_text(readme, encoding="utf-8")
print("SUCCESS: Readme.md updated.")
print("Backup preserved as Readme.md.backup.")

