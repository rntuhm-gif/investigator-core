# investigator-core

Multi-tool investigation orchestrator. Nmap scanning -> traffic/memory/disk forensics -> case management -> report generation.

## Quick Install

```bash
cd investigator-core
pip install -e .
pip install -e ".[full]"   # with all analyzers
```

## Usage

```bash
investigator case create "BH_APT_2026" -d "Suspicious DNS exfiltration" -i "alice,bob"
investigator case list
investigator scan 10.10.10.5 -n "BH_APT_2026" -p 22,80,443
investigator analyze pcap capture.pcap -n "BH_APT_2026"
investigator analyze memory memdump.raw -n "BH_APT_2026"
investigator report "BH_APT_2026" --format html -o report.html
investigator evidence "BH_APT_2026" list
```

## Architecture

```
investigator/
├── cli.py                  # argparse CLI entry point
├── config.py               # JSON config in ~/.investigator/config.json
├── case_manager.py         # CRUD for cases (JSON-backed)
├── scanners/
│   ├── base.py             # abstract scanner interface
│   └── nmap_scanner.py     # python-nmap wrapper
├── analyzers/
│   ├── pcap_analyzer.py    # tshark/pyshark wrapper
│   └── volatility_analyzer.py  # volatility3 wrapper
├── reports/
│   ├── report_generator.py # JSON/text/HTML output
│   └── evidence_locker.py  # file storage per case
└── utils/
    ├── helpers.py
    └── color_out.py
```

Cases are stored as JSON in `~/.investigator/cases/`. Evidence files go into companion directories.

