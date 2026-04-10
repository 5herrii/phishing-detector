# phishing-detector
AI-powered phishing detection tool using VirusTotal and heuristic analysis

# Phishing Detector

A Python-based phishing detection tool that analyzes URLs using heuristic checks and VirusTotal threat intelligence.

## Features
- Detects suspicious URL patterns
- Checks for phishing-related keywords
- Uses VirusTotal domain and URL reputation
- Assigns a risk score
- Returns a verdict such as Likely Safe, Suspicious, or High Risk

## Technologies Used
- Python
- Requests
- tldextract
- VirusTotal API

## How It Works
The tool examines a URL using:
1. Local heuristic checks
2. Keyword-based phishing signals
3. Domain reputation from VirusTotal
4. Exact URL analysis from VirusTotal

## Example Output
```bash
Enter a URL to analyze: br-icloud.com.br

Analyzing URL: http://br-icloud.com.br
Domain      : br-icloud.com.br
Risk Score  : 80/100
Verdict     : HIGH RISK
```
Copy `.env.example` to `.env` and add your VirusTotal API key.

