# MoleHealScanner - Advanced Security Scanner

[![English](https://img.shields.io/badge/lang-English-blue.svg)](README.md) [![Turkish](https://img.shields.io/badge/lang-Türkçe-red.svg)](README_TR.md)

!()[./kariyer-logo.png]
MoleHealScanner is a sophisticated security scanning tool designed to detect sensitive data patterns in codebases. It features parallel processing capabilities and generates detailed, interactive HTML reports with security metrics and visualizations.

## Features

### Scanning Capabilities
- Multi-threaded scanning utilizing all CPU cores
- Comprehensive detection of 250+ sensitive data patterns including:
  - Cryptographic Keys (RSA, DSA, EC, PGP)
  - Cloud Service Credentials (AWS, GCP, Azure)
  - API Keys & Access Tokens
  - OAuth Credentials
  - Payment System Keys (Stripe, PayPal, Square)
  - Database Connection Strings
  - Platform-specific Tokens (GitHub, GitLab, Slack)
- Smart file filtering (excludes binary files like .ttf, .png)
- Shannon entropy analysis to reduce false positives

### Security Reporting
- Interactive HTML reports with:
  - Overall Security Score (0-100)
  - Risk Level Assessment
  - Interactive Data Filtering
  - Severity Distribution Charts
  - Categorized Finding Views
  - Search Functionality
  - Detailed Code Snippets

### Severity Classification
- **Critical** (Level 4): Highest risk credentials (private keys, payment tokens)
- **High** (Level 3): Service account tokens, platform access keys
- **Medium** (Level 2): Generic API keys, webhooks
- **Low** (Level 1): Non-sensitive URLs, general patterns

### False Positive Reduction
- **Entropy Analysis**: Calculates Shannon entropy for each potential secret to measure randomness
- Entropy threshold filtering (default: 3.5) to eliminate low-entropy matches
- Higher entropy values indicate more random strings, which are more likely to be actual secrets

## Usage
```bash
go run main.go <directory_path> --report
```
