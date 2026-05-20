# Vexa Plugin SDK

Vexa exposes a stable plugin API so third parties can extend the engine without forking
`vexa.py`. Plugins are auto-discovered at startup and can register:

- **Static analyzers** — new checks that run during every scan
- **Secret-detection patterns** — additional regex patterns for the secrets analyzer
- **Exploit recipes** — new entries for the AI Console's exploit generator
- **Hooks** — code that runs at scan-pipeline events (pre_scan, post_scan, etc.)
- **Report sections** — custom HTML inserted into enterprise reports
- **CVE enrichment** — attach CVE/CVSS/CWE/impact/fix to findings by ID prefix

**API version:** 1.0.0
**Schema version:** 1
**Backwards compatibility policy:** additive only within 1.x. Breaking changes only on 2.0+.

---

## Getting started

### 1. Create the plugin directory

```bash
mkdir -p vexa_plugins
```

Vexa looks for plugins in `vexa_plugins/` next to `vexa.py` at startup. Any `.py` file
in there is loaded; files starting with `_` are ignored.

### 2. Write a hello-world plugin

```python
# vexa_plugins/hello.py
"""My first Vexa plugin."""
__version__ = "0.1.0"

import sys, importlib
_vexa = sys.modules.get("vexa") or importlib.import_module("vexa")
register_analyzer = _vexa.register_analyzer
Finding = _vexa.Finding
_get_strings = _vexa._get_strings


@register_analyzer("hello-world", platform="android")
def hello_check(ctx):
    if "Hello" in (_get_strings(ctx) or []):
        return [Finding(
            id="hello-world-found",
            title="Hello world string detected",
            severity="info", category="MASVS-CODE",
            description="Demo finding from the hello-world plugin.",
        )]
    return []
```

### 3. Restart Vexa

```
$ python vexa.py
======================================================================
  Vexa - Mobile Application Security Console
======================================================================
  Data folder:     /path/to/vexa_data
  adb:             /usr/bin/adb
  Plugins loaded:  1
  Plugin API:      v1.0.0
  ...
```

The startup banner shows how many plugins loaded. Detailed registration counts
appear in the log. Visit `/api/plugins` to see the full registry.

---

## Extension types

### Analyzers

```python
@register_analyzer(name: str, platform: str = "android")
def my_analyzer(ctx) -> list[Finding]:
    ...
```

The analyzer receives a `Ctx` object with:

- `ctx.apk` — androguard `APK` instance (Android only)
- `ctx.dex_list` — list of `DalvikVMFormat` instances
- `ctx.dx` — `Analysis` object for cross-references
- `ctx.extras` — dict for sharing data between analyzers
- `_get_strings(ctx)` — cached string-pool extraction (use this; don't recompute)

Return a list of `Finding` objects. An empty list is fine.

**Platforms:** `"android"` or `"ios"`. iOS analyzers receive a different `Ctx` shape
(parsed `Info.plist`, Mach-O strings) — see existing iOS analyzers for reference.

### Secret patterns

```python
register_secret_pattern(
    name="My Internal Token",
    pattern=r"mytok_[A-Za-z0-9]{32}",
    kind="api-key",       # free-form classifier
    severity="high",      # critical | high | medium | low | info
    source="my-plugin",   # appears in evidence text
)
```

Patterns are compile-tested at registration. A bad regex raises `VexaPluginError` and
the plugin won't load — Vexa stays running.

### Exploit recipes

```python
register_exploit_recipe(
    key="my-bug-class",
    title="Title shown in the document",
    explanation="One-paragraph summary of the vulnerability class.",
    tags=["my-bug", "weird-thing"],   # any tag matching the user's query triggers this
    build=lambda report: "echo PoC for " + report['metadata']['package'],
    steps=[
        {"title": "Step 1", "detail": "What to do.", "verify": "How you confirm."},
        # ...
    ],
    requirements=["Test device", "ADB on PATH"],
    classification={"cwe": "CWE-XXX", "cvss": 7.5, "masvs": "MSTG-...", "severity": "high"},
    attack_id="T1626",
    attack_name="Abuse Elevation Control Mechanism",
)
```

Once registered, asking the AI Console *"create an exploit for my-bug"* generates a
full enterprise reproduction document using your steps, build function, and metadata.

### Hooks

```python
@register_hook("post_scan")
def my_post_processor(report):
    # Mutate the report dict in place
    for f in report.get("findings", []):
        f.setdefault("metadata", {})["my_tag"] = "yes"
```

**Available events:**

| Event | Signature | When it fires |
|---|---|---|
| `pre_scan` | `(apk_path, ctx)` | Before any analyzer runs |
| `post_scan` | `(report)` | After all analyzers + enrichment finish |
| `pre_finding` | `(finding) -> Optional[Finding]` | Per-finding; return `None` to drop |
| `post_finding` | `(finding)` | After enrichment, before storage |
| `pre_report` | `(report, format_str)` | Before any report (HTML/PDF/Word) is generated |

A hook that raises is logged and skipped — other hooks still run. One bad plugin can't
break the scan pipeline.

### Report sections

```python
@register_report_section("My custom section", position="after_executive_summary")
def render_my_section(report):
    return "<h2>...</h2><p>...</p>"   # raw HTML; "" to skip
```

**Position options:**

- `after_executive_summary`
- `after_attack_surface`
- `after_findings`
- `before_methodology`
- `appendix`

Vexa's report CSS is available — use existing classes (`.box`, `.kpi-row`, `.masvs-table`,
`.roadmap-phase`, etc.) for visual consistency.

### CVE enrichment

```python
register_cve_enrichment("my-bug-class", {
    "cve": "CVE-2024-XXXX",
    "cvss": 8.6,
    "cwe": "CWE-94",
    "masvs": "MSTG-PLATFORM-7",
    "impact": "...",
    "fix": "...",
    "references": ["https://nvd.nist.gov/..."],
})
```

Any finding whose ID starts with `my-bug-class` (or equals it exactly) gets these
fields attached during enrichment, unless they're already set.

---

## API reference

### `Finding` (dataclass)

```python
Finding(
    id: str,                    # unique ID (snake-case-with-dashes recommended)
    title: str,                 # human-readable headline
    severity: str,              # critical | high | medium | low | info
    category: str,              # MASVS-STORAGE | MASVS-CRYPTO | MASVS-AUTH | MASVS-NETWORK | ...
    description: str,           # 1-3 sentence explanation
    evidence: str = "",         # the concrete thing that triggered the finding
    recommendation: str = "",   # short fix recommendation
    cwe: Optional[str] = None,  # e.g. "CWE-89"
    cve: Optional[str] = None,
    cvss: Optional[float] = None,
    masvs: Optional[str] = None,
    impact: str = "",           # business impact paragraph
    fix: str = "",              # full numbered fix steps
    references: list = [],      # list of URLs
    metadata: dict = {},        # plugin-specific extras
    confidence: str = "confirmed",  # confirmed | likely | possible
    source: str = "vexa",       # plugin / analyzer source name
)
```

### Registration helpers

| Function | Purpose |
|---|---|
| `register_analyzer(name, platform)` | Decorator: registers a static analyzer |
| `register_secret_pattern(name, pattern, ...)` | Adds a regex to the secrets scanner |
| `register_exploit_recipe(key, title, ...)` | Adds an entry to the AI Console |
| `register_cve_enrichment(prefix, dict)` | Auto-attach metadata by finding-ID prefix |
| `register_report_section(name, position)` | Decorator: HTML emitter for reports |
| `register_hook(event)` | Decorator: scan-pipeline event handler |

### Discovery & introspection

| Function | Purpose |
|---|---|
| `load_plugins(plugin_dir=None)` | Scan a directory and import every `*.py` file. Called automatically at startup. |
| `list_plugins()` | Return metadata about all loaded plugins. |
| `get_active_analyzers(platform)` | Return the live analyzer list (built-in + plugins) for a platform. |

### REST endpoints

- `GET /api/plugins` — JSON view of registered plugins and registry totals
- `GET /api/health` — includes `plugin_api_version` and `plugins_loaded` count

---

## Versioning policy

| Version family | Compatibility |
|---|---|
| `1.0.x → 1.0.y` | Bug-fix only. No API changes. |
| `1.0.x → 1.y.0` | Additive: new optional fields, new hook events, new keyword args. Plugins keep working. |
| `1.x → 2.0` | Breaking changes possible. Plugins targeting 1.x may need updates. Six-month deprecation notice. |

Check the running API version programmatically:

```python
import vexa
assert vexa.VEXA_PLUGIN_API_VERSION.startswith("1.")
```

Or via REST:

```bash
curl http://127.0.0.1:8000/api/health | jq .plugin_api_version
```

---

## Examples

The `vexa_plugins/` directory ships with four example plugins demonstrating each
extension type:

| File | Demonstrates |
|---|---|
| `example_secrets.py` | Two custom secret patterns |
| `example_analyzer.py` | A static analyzer that emits a Finding |
| `example_recipe.py` | A new exploit recipe (TOCTOU race condition) |
| `example_hook_and_section.py` | A `post_scan` hook + a custom report section |

Read those for canonical usage patterns. They are deliberately simple and well-commented.

---

## Caveats and constraints

- **Plugins run in-process** with full Python privileges. Vet third-party plugins before installing — there is no sandbox.
- **Plugin order is alphabetical** by filename. If two plugins register the same recipe key, the last one wins.
- **Plugins should not import androguard or fastapi at module top level** unless those are pinned in `requirements.txt` — Vexa's import would fail before loading anything.
- **Hook callbacks are synchronous.** A slow hook slows every scan. Keep `post_scan` hooks under a few hundred milliseconds.
- **`pre_finding` hooks can drop findings.** Use this carefully — a buggy filter can hide real vulnerabilities.
- **`Ctx` internals (`apk`, `dex_list`, `dx`) are androguard objects.** Their API may change with androguard major versions; Vexa supports 3.x and 4.x via a runtime path resolver. Stick to `_get_strings(ctx)` and `ctx.extras` for forward-compat.
