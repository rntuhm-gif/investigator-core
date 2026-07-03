# Changelog

All notable changes to investigator-core will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-03

### Added
- **PortScanner** — custom threaded TCP scanner with banner grabbing (`investigator portscan`)
- **HttpScanner** — security header analysis, WAF detection, technology fingerprinting (`investigator http`)
- **SubdomainEnumerator** — DNS brute force with 174-prefix wordlist + crt.sh transparency log (`investigator subdomain`)
- **IOCHarvester** — regex-based extraction of emails, URLs, IPs, domains, hashes (MD5/SHA1/SHA256), CVEs (`investigator analyze ioc`)
- **Workflow Orchestrator** — multi-step pipeline engine with JSON I/O and example templates (`investigator workflow run/example`)
- **WorkflowRunner** — sequential step execution with case attachment and per-step success tracking
- **Rich-based Dashboard** — TUI module (`investigator dashboard`)
- **HTTP features module** — header analysis, WAF signatures, technology detection
- **Helper modules** — `_build_target_list`, port range parser, banner patterns

### Changed
- **CLI** — restructured to support 10+ subcommands (case, scan, portscan, http, subdomain, analyze, workflow, report, evidence, dashboard)
- **Text report** — fixed file extension bug, now correctly saves as `.txt`
- **Config** — added verbose, nmap_timeout, auto_open_report fields
- **CaseManager** — added `add_finding()`, evidence companion directories created on case create

### Fixed
- Text report extension bug (`.text` → `.txt`)
- `__init__.py`/`__main__.py` filename rendering issues
- `evidence_locker.py` missing underscores in filename construction
- HTML report template line break escaping
- Type hints removed where they caused import errors without `from __future__ import annotations`

## [0.1.0] - 2026-07-03

### Added
- Initial release
- **CaseManager** — JSON-backed case CRUD with create/list/load/close/reopen/delete
- **NmapScanner** — python-nmap wrapper with full NSE, timing templates, OS detection
- **PcapAnalyzer** — tshark wrapper for traffic stats, DNS queries, HTTP requests
- **VolatilityAnalyzer** — volatility3 wrapper for memory dumps (Windows/Linux/Mac)
- **ReportGenerator** — JSON, text, HTML output formats
- **EvidenceLocker** — per-case evidence file storage
- **Config** — JSON config in `~/.investigator/config.json`
- **CLI** — argparse with case/scan/analyze/report/evidence subcommands
- **Color output** — ANSI-colored terminal output helper
- **Workflow templates** — initial placeholders for web/ctf/malware/recon

