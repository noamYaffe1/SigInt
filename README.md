# SigInt

**LLM-Driven Web Application Fingerprinting & Discovery**

SigInt is an autonomous reconnaissance tool that uses Large Language Models to intelligently fingerprint web applications and discover all instances across the internet.

## What It Does

1. **Fingerprinting** - Analyzes a target (live site or GitHub repo) to extract unique identifiers
2. **Discovery** - Uses OSINT search engines for internet-connected devices to find matching hosts
3. **Verification** - Actively probes candidates with confidence scoring

```
┌─────────────────────────────────────┐
│           Phase 1                   │
│        Fingerprinting               │
│   ┌─────────────┬───────────────┐   │
│   │  Live Site  │  GitHub Repo  │   │
│   └─────────────┴───────────────┘   │
└──────────────────┬──────────────────┘
                   ▼
         fingerprint.json
                   │
┌──────────────────▼───────────────────┐
│            Phase 2                   │
│           Discovery                  │
│      ┌────────┬────────┐            │
│      │ Shodan │ Censys │            │
│      └────────┴────────┘            │
└──────────────────┬───────────────────┘
                   ▼
         candidates.json
                   │
┌──────────────────▼───────────────────┐
│            Phase 3                   │
│         Verification                 │
│   ┌────────────────────────────┐    │
│   │ Active Probing + Scoring   │    │
│   └────────────────────────────┘    │
└──────────────────┬───────────────────┘
                   ▼
         exports/ (json, csv, html)
```

## Who Should Use It

- **Penetration Testers** - Find all instances of a target application
- **Bug Bounty Hunters** - Discover forgotten deployments
- **Security Researchers** - Track vulnerable application deployments
- **Red Teams** - Map external attack surfaces

## Installation

### Prerequisites

- **Python 3.10+**
- **OpenAI API key** - Required for LLM-powered fingerprinting (both live site and GitHub modes)
- **Discovery API keys** - At least one recommended (Shodan or Censys)
- **IPInfo token** - Optional, for IP geolocation and cloud provider detection

### Setup

```bash
git clone https://github.com/yourusername/SigInt.git
cd SigInt

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Edit .env with your API keys

python main.py config init
# Optional: Edit sigint.yaml to customize settings
```

### API Keys

| Key | Purpose |
|-----|---------|
| `OPENAI_API_KEY` | LLM fingerprinting (required) |
| `SHODAN_API_KEY` | Discovery via Shodan |
| `CENSYS_PERSONAL_ACCESS_TOKEN` | Discovery via Censys |
| `IPINFO_TOKEN` | IP enrichment (geolocation, cloud provider) |
| `GITHUB_TOKEN` | Higher rate limits for GitHub repo analysis |

## Quick Start

```bash
# Full pipeline from GitHub repo
python main.py run --github https://github.com/digininja/DVWA --export json,html

# Full pipeline from live site
python main.py run --live-site https://target-app.com --export json,html

# Interactive mode (review between phases)
python main.py run --live-site https://target-app.com -i --export json,html

# Use existing fingerprint (skip Phase 1)
python main.py run --fingerprint output/fingerprints/app.json --export json,html
```

## Fingerprint Modes

| Mode | Purpose | Best For |
|------|---------|----------|
| `application` | Find all deployments of a software | DVWA, WordPress, Jenkins |
| `organization` | Find all assets of a company/brand | Attack surface mapping |

### Application Mode (Default)

Focuses on **software signatures** that remain constant across deployments. Version numbers are stripped by default to match all versions (v1.0, v2.0, etc.).

- Favicon hashes
- App-specific file paths (`/dvwa/`, `/jenkins/`)
- Default application strings

### Organization Mode

Focuses on **brand/company identifiers** for attack surface mapping:

- Company/brand name in content
- Logo and brand assets
- Copyright notices

```bash
# Application mode (default)
python main.py fingerprint --live-site https://target-app.com

# Organization mode
python main.py fingerprint -l https://target.com --mode organization

# Include version patterns
python main.py fingerprint --live-site https://target.com --include-version
```

## Commands

### Phase 1: Fingerprint

Generate a fingerprint from a live site or GitHub repository.

```bash
# From live site
python main.py fingerprint --live-site https://target-app.com
python main.py fingerprint -l https://target-app.com  # short form

# From GitHub repository
python main.py fingerprint --github https://github.com/user/repo
python main.py fingerprint -g https://github.com/user/repo  # short form
```

**Options:**
| Option | Description |
|--------|-------------|
| `--live-site, -l URL` | Live website URL to fingerprint |
| `--github, -g URL` | GitHub repository URL |
| `-o, --output PATH` | Output file path |
| `-m, --mode MODE` | `application` or `organization` |
| `--include-version` | Include version/year patterns |
| `-i, --max-iterations N` | Max LLM iterations (default: 3) |
| `-v, --verbose` | Enable verbose output |

#### How GitHub Fingerprinting Works

The LLM analyzes the repository source code to extract fingerprint signals:

| What's Analyzed | Examples |
|-----------------|----------|
| **Config Files** | `package.json`, `composer.json`, `README.md` |
| **Route Files** | `routes.py`, `urls.py`, `web.php`, `app.js` |
| **Templates** | `.html`, `.php`, `.twig`, `.blade.php`, `.ejs` |
| **Static Assets** | Favicon, logos (hashed with MMH3/SHA256/MD5) |

The LLM identifies:
- Application name from code and configs
- Distinctive HTML patterns (titles, body content)
- Unique file paths and endpoints
- Static assets for hash-based matching

### Phase 2: Discover

Find candidates matching a fingerprint using OSINT search engines.

```bash
python main.py discover output/fingerprints/app.json
python main.py discover output/fingerprints/app.json --export csv,html
```

**Options:**
| Option | Description |
|--------|-------------|
| `-o, --output PATH` | Output file path |
| `--max-queries N` | Max queries to generate (default: 10) |
| `--max-candidates N` | Limit candidates after deduplication |
| `--cache-strategy` | `cache_only`, `new_only`, `cache_and_new` |
| `--cache-ttl DAYS` | Cache expiration (default: 7) |
| `--plugins NAMES` | Plugins to use (e.g., `shodan,censys`) |
| `--skip-enrichment` | Skip IPInfo enrichment |
| `--enrich-workers N` | Concurrent enrichment workers (default: 20) |
| `--export FORMATS` | Export candidates (`json,csv,html`) |
| `--export-dir PATH` | Export directory (default: output/exports) |
| `--list-plugins` | List available plugins |
| `-v, --verbose` | Enable verbose output |
| `-i, --interactive` | Review/approve each query before execution |

### Phase 3: Verify

Actively probe candidates and score matches.

```bash
python main.py verify fingerprint.json candidates.json --export json,csv,html
python main.py verify fingerprint.json candidates.json -w 30 -t 15 --export csv,html
```

**Options:**
| Option | Description |
|--------|-------------|
| `-w, --workers N` | Concurrent workers (default: 10) |
| `-t, --timeout SEC` | Request timeout (default: 10) |
| `--skip-tls` | Skip TLS certificate fetching |
| `--skip-tcp-check` | Skip TCP liveness check (not recommended) |
| `--weights WEIGHTS` | Custom probe weights |
| `--interactive-weights` | Interactively set probe weights |
| `--export FORMATS` | Export formats (`json,csv,html`) |
| `--export-dir PATH` | Export directory |
| `--min-score N` | Minimum score for export |
| `-v, --verbose` | Enable verbose output |

### Export

Export results to different formats.

```bash
python main.py export results.json csv,html
```

## Scoring System

Each matched probe adds points to the total score (capped at 100):

| Probe Type | Points |
|------------|--------|
| `favicon_hash` | 80 |
| `image_hash` | 50 each |
| `title_match` | 15 |
| `body_match` | 15 each |

### Classification

| Classification | Score |
|---------------|-------|
| **Verified** | ≥ 80 |
| **Likely** | ≥ 50 |
| **Partial** | ≥ 30 |
| **Unlikely** | > 0 |

### Scoring Features

- **Partial Matching** - Title and body patterns scored independently
- **Early Termination** - Stops probing when score reaches 100
- **Scheme Fallback** - Tries alternate HTTP/HTTPS if score < 50%

## Configuration

Generate a config file:

```bash
python main.py config init
```

Example `sigint.yaml`:

```yaml
fingerprint:
  max_iterations: 3
  model: "gpt-4o"
  mode: "application"

discovery:
  max_queries: 10
  cache_ttl_days: 7
  enabled_plugins:
    - shodan
    - censys

verification:
  timeout: 10
  workers: 10
  probe_points:
    favicon_hash: 80
    image_hash: 50
    title_match: 15
    body_match: 15
  score_thresholds:
    verified: 80
    likely: 50
    partial: 30

export:
  default_formats: [json, csv, html]
```

## Discovery Plugins

| Plugin | Required Keys |
|--------|---------------|
| `shodan` | `SHODAN_API_KEY` |
| `censys` | `CENSYS_PERSONAL_ACCESS_TOKEN` |

See [`plugins/discovery/README.md`](plugins/discovery/README.md) for creating custom plugins.

## Performance Features

- **TCP Liveness Check** - Fast pre-check before HTTP probing (skips dead hosts)
- **Connection Pooling** - Reuses HTTP connections for efficiency
- **Concurrent Workers** - Parallel verification with configurable threads
- **Query Caching** - Configurable TTL (default 7 days)
- **Smart Query Limiting** - Filters generic patterns, limits queries by default
- **App Prefix Fallback** - Tries `/appname/` path if root fails (application mode)

### Query Filtering

Generic patterns are automatically filtered to save API tokens:
- Frameworks: Bootstrap, jQuery, React, Angular, Vue
- Common UI: Login, Search, Home, Dashboard
- Generic: Twitter, Facebook, Copyright

## Output Structure

```
output/
├── cache/queries/       # Cached API results
├── candidates/          # Discovered candidates
├── exports/             # JSON, CSV, HTML reports
└── fingerprints/        # Fingerprint specs
```

## Interactive Mode

Human-in-the-loop control over the entire pipeline:

```bash
# Full pipeline with interactive mode
python main.py run --live-site https://target.com -i --export json,html

# Standalone discover with interactive query review
python main.py discover fingerprint.json -i
```

### What Interactive Mode Does

| Phase | Interactive Feature |
|-------|---------------------|
| **After Phase 1** | Review fingerprint before spending API credits |
| **Phase 2 Queries** | Approve/deny/modify each query before execution |
| **After Phase 2** | Review candidates before verification |
| **After Phase 3** | Review results before export |

### Query Review Options

When reviewing discovery queries:
- `[A]pprove` - Run this query as-is
- `[D]eny` - Skip this query (save API tokens)
- `[M]odify` - Edit the query value before running
- `[R]un all` - Approve all remaining queries
- `[S]kip all` - Skip all remaining queries

This gives you full control to:
- Skip generic queries that might return too many results
- Modify queries to be more specific
- Stop early if results look incorrect

## Debug Mode

```bash
# Use --verbose flag on any command
python main.py fingerprint --live-site https://target.com --verbose
python main.py discover fingerprint.json --verbose
python main.py verify fingerprint.json candidates.json --verbose
python main.py run --live-site https://target.com --verbose

# Or set environment variable
SIGINT_DEBUG=1 python main.py run --live-site https://target.com
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No candidates found | Check API keys, verify fingerprint queries, try more plugins |
| Low scores | Try `--interactive-weights`, check scheme fallback |
| Rate limiting | Reduce `-w/--workers`, use `--cache-strategy cache_and_new` |
| Slow verification | Increase `-w` workers, TCP check filters dead hosts automatically |
| Connection errors | Try `--skip-tcp-check` if firewall blocks TCP probes |

## License

MIT License - See LICENSE file.

## Disclaimer

This tool is for authorized security testing only. Users are responsible for ensuring they have permission to scan target systems.
