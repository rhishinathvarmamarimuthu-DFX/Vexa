# Vexa — Mobile Application Security Console

A single-file, locally-hosted static analysis and dynamic-testing tool for Android APKs and iOS IPAs.

## What it does

- **91 Android analyzers + 15 iOS analyzers + 39 secret patterns** — covers OWASP MASVS, MASTG, and named CVEs (Janus, StrandHogg, Dirty Stream, jackson-databind, etc.)
- **MASVS compliance overview** — pass / warn / fail per OWASP MASVS category
- **Per-finding CVE / CVSS / Impact / Fix** — with authoritative reference links
- **AndroidManifest.xml viewer** — inline syntax-highlighted XML with clickable component navigation
- **Component inspector** — every Activity / Service / Receiver / Provider with parsed exported state, permissions, intent filters
- **Auto-PoC engine** — generates Frida hooks, deep-link payloads, intent spoofing scripts, MITM setup
- **AI Console** — local rule-based exploit assistant with on-demand PoC generation. Optional Ollama integration for free-form chat
- **Dynamic Testing** — full ADB integration: launch / kill / clear / screenshot / logcat / custom intent / per-component fuzzing
- **Reports** — JSON, HTML, PDF, Word, Excel exports
- **Store URL fetch** — accepts Play Store URLs and downloads via APKPure / APKCombo

## Privacy

Vexa runs entirely on your machine. Uploaded files, scan reports, and chat history never leave your computer. The tool makes outbound HTTPS requests in only three cases, all opt-in:

1. When you click "Fetch from store URL" (downloads an APK from APKPure or APKCombo).
2. When you query a local Ollama instance from the AI Console (loopback only).
3. When you click an external reference link in a finding (opens in your browser).

There is no telemetry, no analytics, no auto-update check, no remote logging.

## Quick start

```bash
pip install -r requirements.txt
python vexa.py
```

Then visit http://127.0.0.1:8000 — you'll be guided through a one-time setup wizard to create an administrator account.

## Requirements

- Python 3.9 or newer
- See `requirements.txt` for Python packages
- Optional: Android `adb` on PATH (for dynamic testing)
- Optional: [Ollama](https://ollama.com) running locally (for free-form LLM chat)
- Optional: Frida + frida-server on the test device (for runtime instrumentation)

## Configuration

| Environment variable | Purpose | Default |
|---|---|---|
| `VEXA_HOST` | Bind address | `127.0.0.1` |
| `VEXA_PORT` | Listen port | `8000` |
| `VEXA_DATA_DIR` | Override data directory | `vexa_data/` next to script |

## Data directory layout

```
vexa_data/
├── uploads/      # Uploaded APK/IPA files
├── reports/      # JSON scan reports (one per scan)
├── pulled/       # Files pulled from devices via dynamic test
vexa_config.json  # Admin credentials (created on first run)
```

## Security

See [SECURITY.md](SECURITY.md) for the threat model, security controls, and how to report a vulnerability.

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgements

This tool builds on the work of the OWASP Mobile Application Security project (MASVS / MASTG), the androguard maintainers, and the broader mobile-security research community. CVE references link to the National Vulnerability Database.
