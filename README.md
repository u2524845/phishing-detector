# 🔍 Phishing Detection Tool

A lightweight Python-based phishing URL detection tool with a web dashboard. Analyzes URLs using rule-based heuristics to identify suspicious characteristics and assign a risk score.

## Features

- **URL Risk Assessment**: Analyzes URLs and assigns a risk score (0-100)
- **Domain Analysis**: Extracts and displays domain information
- **Heuristic Checks**: 10 different security checks:
  - IP address detection
  - Suspicious keywords (login, verify, account, etc.)
  - @ symbol in URL
  - Excessive URL length
  - Excessive subdomains
  - Suspicious TLDs (.tk, .ml, .ga, etc.)
  - HTTP vs HTTPS protocol
  - Domain hyphens
  - URL shorteners
  - Brand impersonation
- **Interactive Web Dashboard**: Clean, single-page interface with real-time analysis
- **Risk Levels**: 🟢 Safe (0-19), 🟡 Suspicious (20-49), 🔴 Dangerous (50+)

## Setup

### Prerequisites
- Python 3.7+
- pip

### Installation

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Tool

```bash
# Make sure virtual environment is activated
source venv/bin/activate

# Start the Flask server
python app.py
```

The dashboard will be available at `http://localhost:5000`

## Usage

1. Open your browser and go to `http://localhost:5000`
2. Enter a URL in the input field
3. Click "Check URL" to analyze
4. View the risk score and detailed security checks

### Example Test URLs

- **Safe**: `https://google.com`, `https://github.com`
- **Suspicious**: `http://192.168.1.1/login`, `https://paypa1-secure.tk/verify`
- **Dangerous**: `http://bit.ly/login`, URLs with multiple red flags

## Project Structure

```
.
├── app.py              # Flask application and routes
├── analyzer.py         # URL analysis engine with all heuristics
├── requirements.txt    # Python dependencies
├── templates/
│   └── index.html      # Web dashboard UI
├── static/
│   └── style.css       # Dashboard styling
└── venv/              # Virtual environment (created during setup)
```

## How It Works

### Heuristic Scoring System

Each URL is checked against 10 different heuristics. Each triggered check adds points to the final score:

| Check | Points |
|-------|--------|
| URL Shortener | +51 |
| IP Address | +20 |
| Suspicious Keywords | +20 |
| HTTP (not HTTPS) | +25 |
| Suspicious TLD | +25 |
| @ Symbol | +10 |
| Excessive URL Length | +10 |
| Excessive Subdomains | +10 |
| Domain Hyphens | +5 |
| Brand Impersonation | +5 |

**Total Maximum Score: 100**

### Risk Levels

- **🟢 Safe (0-19)**: URL appears legitimate - safe to visit
- **🟡 Suspicious (20-49)**: URL has warning signs - verify before clicking
- **🔴 Dangerous (50+)**: URL shows strong phishing indicators - do not click

## Technology Stack

- **Backend**: Python 3, Flask
- **URL Analysis**: tldextract, regex pattern matching
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Libraries**:
  - flask: Web framework
  - tldextract: Domain parsing
  - python-whois: Domain information (optional)
  - requests: HTTP client

## Limitations

- Rule-based detection (no machine learning)
- Cannot verify actual website content
- Does not check known phishing databases in real-time
- Domain age checking requires external WHOIS lookup
- May have false positives/negatives

## Future Enhancements

- Integration with PhishTank or OpenPhish API for real-time threat database
- ML classifier trained on labeled phishing datasets
- Browser extension version
- URL history and analytics dashboard
- API rate limiting and authentication
- Persistent database for analysis history

## License

Open source - feel free to use and modify

## Author

Built with Python and Flask
