# Vexa Release Checklist

A pre-flight verification list. Run through this before shipping any new Vexa build to a
customer or pushing a tagged release. Tick every box (or document the deliberate exception).

---

## 1. Build integrity

- [ ] `python3 -m py_compile vexa.py` exits 0
- [ ] `python3 test_vexa.py` runs all test classes with **0 failures**
- [ ] SHA-256 of `vexa.py` recorded in the release notes
- [ ] `requirements.txt` is in sync with what the build actually imports
- [ ] No leftover `print()` debug statements in the source (`grep -nE "^\s*print\(" vexa.py` → empty)
- [ ] No `TODO` / `XXX` / `FIXME` for shipping items (`grep -nE "TODO|XXX|FIXME" vexa.py`)

## 2. Authentication & sessions

- [ ] First-run setup wizard appears on a clean install (no `vexa_config.json` present)
- [ ] Setup rejects passwords < 12 chars
- [ ] Setup rejects passwords missing lowercase / uppercase / digit
- [ ] After setup, `vexa_config.json` has permissions `0o600` on Unix
- [ ] Login with correct credentials redirects to home
- [ ] Login with wrong credentials shows "Invalid credentials" (no user-enumeration leak)
- [ ] After 5 failed login attempts from same IP, 6th attempt returns HTTP 429
- [ ] After login, `Set-Cookie` includes `HttpOnly` and `SameSite=Strict`
- [ ] When served over HTTPS, cookie also has `Secure` flag
- [ ] Logout clears the session cookie and invalidates the server-side session

## 3. CSRF protection

- [ ] All POST/PUT/PATCH/DELETE endpoints reject requests missing `X-Vexa-Csrf` header (403)
- [ ] CSRF token is rotated per session (each fresh login gets a new one)
- [ ] Frontend `fetch()` wrapper attaches the header automatically
- [ ] XHR uploads (the FormData scan upload) attach the header
- [ ] Token survives a page reload (refetched from `/api/csrf` after login)

## 4. Path-traversal defenses

- [ ] `_validate_scan_id` rejects: `../etc/passwd`, `..\foo`, `a/b`, `a\b`, paths with spaces, length < 8 or > 64
- [ ] `_validate_scan_id` accepts UUIDs and hex tokens (`abc12345`, 64-char strings)
- [ ] `_safe_binary_path` returns `None` for `apk_path` outside the `uploads/` directory
- [ ] `_safe_binary_path` returns `None` for non-existent files
- [ ] Direct GET to `/api/scan/<traversal>/report.json` returns 400, not 200/500

## 5. Reports tab — CRUD operations (this matters because the delete bug was here)

- [ ] Reports tab loads and lists every saved scan
- [ ] Filter input narrows results live as user types
- [ ] Refresh button re-queries the list
- [ ] **Open** button loads the selected scan into the analysis panes
- [ ] **Download** buttons (HTML/PDF/Word/Excel/JSON) each return the right file
- [ ] **Delete** button shows confirm dialog
- [ ] Delete button after confirmation actually deletes:
  - [ ] the JSON report
  - [ ] the original APK/IPA file
  - [ ] the `*.dynamic.json` side-file (if present)
  - [ ] the `*.pocs.json` side-file (if present)
  - [ ] the `<sid>_pocs/` artifact directory (if present)
- [ ] After delete, the scan disappears from the Reports list immediately
- [ ] After delete, the scan disappears from the sidebar saved-scans list
- [ ] Deleting the currently-loaded scan returns the UI to the welcome screen
- [ ] Delete works whether the package name contains spaces, quotes, apostrophes, or unicode

## 6. AI Console — exploit generator

- [ ] `_generate_exploit` returns a structured doc (not None) for each of these queries:
  - [ ] `"create an exploit for SQL injection"`
  - [ ] `"build a poc for webview rce"`
  - [ ] `"I want exploit"`
  - [ ] `"I want an exploit for sqli"`
  - [ ] `"how do I exploit this app?"`
  - [ ] `"show me how to exploit the webview"`
  - [ ] `"demonstrate the addjavascriptinterface vulnerability"`
  - [ ] `"exploit for ssl pinning"`
  - [ ] `"give me exploit scenario"`
  - [ ] `"walk me through the SQL injection"`
  - [ ] `"sqli payload"` (bare vuln vocab, no verb)
- [ ] Returns `None` for non-exploit queries: `"what is sql injection?"`, `"summary"`, `"list findings"`
- [ ] Output for any recipe match has all 11 sections + classification header
- [ ] Output references `CVSS v3.1`, `CWE-XXX` (linked to MITRE), `MITRE ATT&CK`
- [ ] Output includes verify gates ("✓ Verify:") in reproduction steps
- [ ] When the query mentions a finding from the actual scan, the output uses that finding's CVE/CVSS/evidence
- [ ] When there is no recipe match and no finding match, fallback gives a scenario built from the top-severity finding
- [ ] When the scan is empty and no recipe matches, fallback shows the available-recipes menu

## 7. Static analyzers — false positive control

- [ ] `analyze_cipher_no_padding` does NOT flag when `Cipher` class is absent
- [ ] `analyze_cipher_no_padding` does NOT flag when a qualified `AES/MODE/PADDING` form exists
- [ ] `analyze_cipher_no_padding` flags ONLY when both signals are present
- [ ] All findings with `confidence: possible` are clearly marked as such in the UI
- [ ] Run a known-clean APK through Vexa: count of findings should be small (informational only)
- [ ] Run a known-vulnerable APK (OVAA, DIVA): findings include the vulnerabilities those apps demonstrate

## 8. Auto PoCs — quality filter

- [ ] PoCs are NOT generated for `info` severity findings
- [ ] PoCs are NOT generated for `low` severity findings (unless confidence is `confirmed`)
- [ ] PoCs are NOT generated for `confidence: possible` findings
- [ ] PoCs are NOT generated for findings with no evidence string
- [ ] PoCs are NOT generated for findings outside known MASVS buckets
- [ ] PoC count for a representative scan is small (single digits to low double digits, not 80+)

## 9. Reports — enterprise content

- [ ] HTML report has cover page with risk-rating badge
- [ ] HTML report has clickable Table of Contents at the top
- [ ] HTML report has Executive Summary with top-5 recommendations
- [ ] HTML report has OWASP MASVS Compliance Status table (8 categories)
- [ ] HTML report has Remediation Roadmap with Phase 1 / 2 / 3 SLAs
- [ ] HTML report has Methodology & Scope appendix
- [ ] PDF export renders identically to HTML (or close to it)
- [ ] Word (.docx) export opens cleanly in Microsoft Word and LibreOffice
- [ ] Excel (.xlsx) export has separate sheets for findings, summary, metadata
- [ ] JSON export contains every field the UI uses

## 10. Frida / Tools tab

- [ ] All 16 tool tiles render in the grid
- [ ] Clicking any tile loads its cheatsheet without a 404
- [ ] Cheatsheets are parameterised against the current scan's package name
- [ ] Copy button on the script viewer actually copies to clipboard

## 11. Dynamic Testing tab

- [ ] Tab shows "no devices connected" cleanly when ADB has no devices
- [ ] Tab shows the ADB-detected device list when one or more is connected
- [ ] Quick Actions (launch / kill / clear / pull / logcat / dumpsys / screenshot / netstat) all return without error
- [ ] Custom Intent Builder accepts well-formed input and returns the adb command output
- [ ] Logcat panel updates with output when "Tail 100" is clicked
- [ ] Screenshot embeds the captured PNG inline

## 12. Privacy & data handling

- [ ] No outbound network calls except: store-URL fetch (when user clicks), Ollama (loopback), reference-link clicks
- [ ] No telemetry, analytics, or auto-update check fires on launch (`tcpdump` while booting)
- [ ] Privacy banner visible on the welcome page
- [ ] Logout does NOT delete saved scans (verify by logout → login → scans still listed)

## 13. Error handling

- [ ] 500-level error returns a generic message — full traceback only in server logs
- [ ] Validation errors return 422 with a generic "Invalid request body"
- [ ] OpenAPI / Swagger UI is disabled (visiting `/docs` returns 404)
- [ ] CORS is locked down (`allow_origins=[]`)

## 14. Documentation

- [ ] README.md mentions the first-run setup wizard
- [ ] SECURITY.md threat model is current
- [ ] LICENSE present and correct
- [ ] Release notes mention every behaviour change since previous version
- [ ] Known issues / caveats listed

## 15. Performance & resource limits

- [ ] Upload of a 200 MB APK completes within 60 seconds on a developer laptop
- [ ] Static scan of a typical APK (10–50 MB) completes within 30 seconds
- [ ] Memory consumption stays under 1 GB for typical APKs
- [ ] Chat input over 4 KB is rejected with a clear error
- [ ] Conversation > 100 messages is rejected with a clear error

---

## Sign-off

- Build SHA-256: ____________________________________________
- Build date: __________
- Tested by: __________
- Approved by: __________
- Notes / known exceptions: __________
