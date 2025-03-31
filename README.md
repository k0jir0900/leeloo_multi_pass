# Leeloo Multi Pass

`Leeloo Multi Pass` is an interactive command-line tool for analyzing Indicators of Compromise (IoCs), such as IP addresses, URLs, and file hashes. It provides a simple text-based interface to analyze individual values or entire files using specialized scripts.

## 🧠 Features

- Supports analysis of:
  - IP addresses
  - URLs
  - Hashes (MD5/SHA256)
- Validation can be done for single entries or entire files
- Uses public threat intelligence APIs

## ▶️ Usage
1.- Register your API keys in the `secret.json` file.

2.- Run the tool with the following command:

```bash
python3 main.py
```

## 🔎 API
This tool integrates with the following public APIs:

- IPInfo
- AbuseIPDB
- ThreatFox
- Alienvault
- URL Scan