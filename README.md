# investigator-core

[![Version](https://img.shields.io/badge/version-0.2.0-blue.svg)](https://github.com/rntuhm-gif/investigator-core/releases)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)]()

A modular, multi-tool investigation framework for CTFs, lab environments, and authorized security testing. Orchestrates Nmap, custom port/HTTP/subdomain scanners, traffic/memory/IOC forensics, multi-step workflow pipelines, and case management with report generation — all from a single CLI.

## Features

- **Case Management** — JSON-backed case files with evidence tracking, findings, notes, and status (open/closed)
- **Nmap Scanner** — full NSE support, custom args, sudo, timeout control
- **Custom Port Scanner** — threaded TCP, banner grabbing, configurable timeout
- **HTTP Scanner** — security header analysis, WAF detection, technology fingerprinting
- **Subdomain Enumerator** — DNS brute force + crt.sh transparency log
- **IOC Harvester** — extract emails, URLs, IPs, domains, hashes (MD5/SHA1/SHA256), CVEs from any text/PCAP/log
- **PCAP Analyzer** — packet stats, protocol hierarchy, DNS queries, HTTP requests (tshark)
- **Memory Analyzer** — Volatility 3 wrapper for memory dumps (Windows/Linux/Mac)
- **Workflow Orchestrator** — chain multiple tools into pipelines with example templates
- **Report Generator** — JSON, text, and self-contained HTML reports
- **Interactive Dashboard** — Rich-based TUI (coming in v0.3.0)

## Installation

### From PyPI (once published)

```bash
pip install investigator-core
```

### From source

```bash
git clone https://github.com/rntuhm-gif/investigator-core.git
cd investigator-core
pip install -e .

# With all optional analyzers
pip install -e ".[full]"

# With PCAP analysis only
pip install -e ".[pcap]"

# With memory analysis only
pip install -e ".[memory]"
```

### Dependencies

| Component | Tool | Install |
|---|---|---|
| Nmap scanning | `python-nmap` | `pip install python-nmap` (also requires `nmap` binary) |
| Port scanning | built-in (sockets + threads) | none |
| HTTP scanning | `requests`, `urllib3` | included |
| Subdomain enum | `requests` | included |
| IOC extraction | built-in (regex) | none |
| PCAP analysis | `tshark` + `pyshark` | `sudo apt install tshark` + `pip install pyshark` |
| Memory forensics | `volatility3` | `pip install volatility3` |
| Disk forensics | `sleuthkit` + `pytsk3` | `sudo apt install sleuthkit` + `pip install pytsk3` |

## Quick Start

```bash
# Create a case
investigator case create "HTB_Box" -d "Box enumeration" -i "you"

# Run scans
investigator scan 10.10.10.5 -n "HTB_Box" -p 22,80,443 --args "-sV -sC -T4"
investigator portscan 10.10.10.5 -p 1-65535 -t 200 --banner -n "HTB_Box"
investigator http https://10.10.10.5 -n "HTB_Box"
investigator subdomain target.htb -n "HTB_Box"

# Analyze evidence
investigator analyze pcap capture.pcap -n "HTB_Box"
investigator analyze memory memdump.raw -n "HTB_Box"
investigator analyze ioc /var/log/apache2/access.log -n "HTB_Box"

# Run a workflow pipeline
investigator workflow example web      # creates a web recon template
investigator workflow run /tmp/web_workflow.json

# Generate a report
investigator report "HTB_Box" --format html -o report.html
investigator report "HTB_Box" --format json -o report.json
investigator report "HTB_Box" --format text

# List evidence
investigator evidence "HTB_Box" list
```

## Architecture

```
investigator/
├── cli.py                  # argparse CLI entry point
├── config.py               # JSON config in ~/.investigator/config.json
├── case_manager.py         # CRUD for cases (JSON-backed)
├── dashboard.py            # Rich-based TUI dashboard
├── scanners/
│   ├── base.py             # abstract scanner interface
│   ├── nmap_scanner.py     # python-nmap wrapper
│   ├── port_scanner.py     # threaded TCP scanner
│   ├── http_scanner.py     # HTTP/header/WAF detection
│   └── subdomain_enum.py   # DNS brute + crt.sh
├── analyzers/
│   ├── pcap_analyzer.py    # tshark/pyshark wrapper
│   ├── volatility_analyzer.py  # volatility3 wrapper
│   └── ioc_harvester.py    # regex-based IOC extraction
├── orchestrator/
│   ├── workflow.py         # workflow definition + JSON I/O
│   └── runner.py           # step execution engine
├── reports/
│   ├── report_generator.py # JSON/text/HTML output
│   └── evidence_locker.py  # file storage per case
└── utils/
    ├── helpers.py
    └── color_out.py
```

## Data Storage

- **Cases** → `~/.investigator/cases/<name>.json`
- **Evidence files** → `~/.investigator/cases/<name>_evidence/`
- **Config** → `~/.investigator/config.json`

## Workflow Examples

Built-in templates generate ready-to-run JSON pipelines:

```bash
investigator workflow example web       # Web app recon: subdomain + http + nmap + ioc
investigator workflow example ctf       # CTF box: full portscan + nmap -A
investigator workflow example malware   # Malware triage: ioc + memory
investigator workflow example recon     # Full external recon
```

Edit the generated JSON to swap targets, then run:

```bash
sed -i 's/TARGET/your-target.com/g' /tmp/web_workflow.json
investigator workflow run /tmp/web_workflow.json -n "MyCase"
```

## Use Cases

- **CTF competitions** — Hack The Box, TryHackMe, VulnHub boxes
- **Lab environments** — personal practice, OSCP-style exercises
- **OSCP/Pentest+ prep** — build muscle memory around common recon/analysis workflows
- **Forensics practice** — PCAP and memory dump analysis with case tracking
- **Tool development** — extensible base classes for adding custom scanners/analyzers

## License

MIT License — see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for **authorized security testing, CTF competitions, and educational lab environments only**. Do not use against systems you do not own or have explicit written permission to test. The authors are not responsible for misuse.

## Contributing

Pull requests welcome. For major changes, open an issue first to discuss what you'd like to change.

## Links

- [Repository](https://github.com/rntuhm-gif/investigator-core)
- [Issues](https://github.com/rntuhm-gif/investigator-core/issues)
- [Changelog](CHANGELOG.md)

