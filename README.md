# OHRA — Local LLM Integration + WCAT Module

> **Note:** This is not my original project. OHRA (Open Honeypot with Response
> Automation) was originally developed and published by its authors at NordSec
> 2025. This repository contains my additions, bug fixes, and research
> extensions built on top of their work as part of my M.Tech AI thesis at CDAC
> Mohali under IK Gujral Punjab Technical University.
>
> Original OHRA paper: *"OHRA: An Open Honeypot with Response Automation"* —
> NordSec 2025, Springer LNCS.

---

## Current Status

This is a **work in progress** as part of an ongoing M.Tech AI thesis (~8 months
remaining). The thesis title, base paper selection, and AI modules listed below
are **proposals under active consideration** — not finalized decisions.

**What is done:**
- Local LLM integration (Ollama + Llama 3.1)
- WCAT malware analysis module (built from scratch, integrated across 4 protocols)
- 20 bug fixes in the original OHRA codebase
- System running and tested locally

**What is in progress:**
- Studying HoneyGPT (Computer Networks 2026) to understand how its intent
  analysis and system-state tracking could complement or integrate with OHRA's
  multi-protocol architecture
- Literature survey across ShelLM, OHRA, HoneyGPT, DecoyPOT to identify
  research gaps
- Base paper selection not yet finalized

**What is planned (thesis proposal — not implemented yet):**
1. LSTM-based anomaly detection on attacker command sequences
2. Attacker behaviour classification (MITRE ATT&CK stages)
3. RAG-enhanced adaptive response generation
4. Perception engineering — measuring honeypot deception effectiveness

---

## Proposed Thesis Direction

**Working title (not final):**
MIRAGE: Multi-protocol Intelligent Response using Adaptive Generative Environments

**Direction:** Build an AI-driven adaptive cyber deception framework that goes
beyond static LLM response generation toward a system that observes attacker
behaviour, learns from it, and adapts its deception strategy in real time.

This is inspired by the gap identified in DecoyPOT (Computers & Security,
Elsevier Q1) which explicitly states real-time adaptability as future work —
the shift from *Retrieve → Generate → Respond* to *Observe → Learn → Adapt →
Generate better deception*.

**Target venue:** IEEE publication

---

## What I Added to OHRA

The original OHRA used OpenAI's cloud API (GPT-4o-mini) and had no malware
analysis capability. This fork adds:

### 1. Local LLM Integration (Ollama)
- Replaced OpenAI cloud API with Llama 3.1 8B running locally via Ollama
- Zero cost per request, fully offline, no attacker data leaves the machine
- Works on Mac (Apple Silicon) and Linux

### 2. WCAT — Web Content Analysis Tool
A malware capture and static analysis microservice built from scratch:
- Intercepts curl/wget commands across SSH, HTTP, Telnet, FTP honeypots
- Shows attacker a fake progress bar while silently downloading the real file
- Runs 5 static analysis techniques: magic-byte detection, entropy, string
  extraction, hash generation, embedded URL scan
- 12 YARA-style signature rules — verdict: CLEAN / SUSPICIOUS / MALICIOUS
- Auto-resets container via Docker socket API on MALICIOUS detection
- Archives malware as password-protected ZIP (password: infected — industry
  standard used by VirusTotal, MalwareBazaar, CERT-In) to host machine before
  reset

### 3. Bug Fixes (20 total)
Key fixes in the original codebase:
- Port mismatch between uWSGI and Docker (HTTP/IPP honeypots unreachable)
- Flask root route missing methods=HTTP_METHODS (POST on / returned 405)
- SSH session dying after one command (missing .encode() on prompt send)
- SSH backspace, arrow key history, PTY acknowledgement, idle timeout
- Telnet inline imports shadowing module-level names (session crash on LLM call)
- traceback.format_exc missing () — function reference passed instead of value
- LLM request timeout too short (20s to 60s) for local Llama 3.1
- Docker depends_on YAML indentation broken across all 7 honeypot services
- Missing curl in llmhandler/loghandler Dockerfiles (healthcheck always failing)
- Debian apt mirror over HTTP timing out — switched to HTTPS

---

## Architecture

```
Attacker
    |
Multi-protocol Honeypots (SSH · HTTP · Telnet · FTP · IPP · SMTP)
    |                          |
LLM Handler                Log Handler
(LangChain + LangGraph)    (JSON session logs)
(Llama 3.1 via Ollama)
(MemorySaver — per-attacker memory)
    |
    | (if curl/wget detected)
WCAT — port 8002
(download → analyze → classify → archive → auto-reset)
    |
~/Desktop/wcat_malware_archive/
    |-- downloads/   (raw binaries + JSON reports)
    └-- archive/     (password-protected ZIPs)
```

---

## Prerequisites

- Docker Desktop (Mac/Linux)
- Ollama installed and running
- Llama 3.1 model pulled

```bash
brew install ollama
ollama serve &
ollama pull llama3.1
```

---

## Setup

```bash
git clone https://github.com/SimranArora2/OHRA-local-llm.git
cd OHRA-local-llm

mkdir -p ~/Desktop/wcat_malware_archive/downloads
mkdir -p ~/Desktop/wcat_malware_archive/archive

cd src
docker compose up --build
```

---

## Services

| Service        | Port | Description                          |
|----------------|------|--------------------------------------|
| HTTP Honeypot  | 8080 | Flask web server persona             |
| SSH Honeypot   | 2222 | Ubuntu 22.04 LTS persona             |
| Telnet Honeypot| 2323 | Cisco ISR 4331 router persona        |
| IPP Honeypot   | 8631 | Network printer persona              |
| WCAT           | 8002 | Malware analysis microservice        |
| Log Handler    | 8000 | Session + event logging (internal)   |
| LLM Handler    | 8001 | Ollama interface (internal)          |

---

## Testing

```bash
# SSH
ssh-keygen -R "[localhost]:2222" 2>/dev/null
ssh -o StrictHostKeyChecking=no -p 2222 root@localhost

# HTTP
curl -X POST http://localhost:8080/admin \
  -d '{"username":"admin","password":"1234"}'

# Telnet
nc localhost 2323

# WCAT malware detection
curl -X POST http://localhost:8002/analyze \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://www.eicar.org/download/eicar.com.txt"]}'

# Check results after ~10 seconds
ls -la ~/Desktop/wcat_malware_archive/archive/
cat ~/Desktop/wcat_malware_archive/downloads/*_report.json
```

---

## WCAT Report Format

```json
{
  "url": "https://example.com/malware.sh",
  "timestamp": "2026-07-06T06:35:33Z",
  "status": "success",
  "file_info": {
    "sha256": "275a021b...",
    "md5": "44d88612...",
    "size_bytes": 68,
    "detected_type": "Text File"
  },
  "static_analysis": {
    "entropy": 4.87,
    "entropy_interpretation": "Medium — mixed content",
    "strings_count": 1,
    "strings_sample": ["EICAR-STANDARD-ANTIVIRUS-TEST-FILE"]
  },
  "threat_classification": {
    "verdict": "MALICIOUS",
    "severity": "HIGH",
    "matched_rules": [{"rule": "EICAR Test File", "severity": "HIGH"}],
    "note": "Submit SHA256 to https://virustotal.com for confirmation"
  }
}
```

---

## Useful Commands

```bash
# Reset SSH host key after container restart
ssh-keygen -R "[localhost]:2222" 2>/dev/null

# View logs
docker logs src-ssh-pot-1 --tail 30
docker logs src-wcat-1 --tail 30
docker logs src-llmhandler-1 --tail 30

# Stop everything
cd src && docker compose down
```

---

## Credits

- Original OHRA: published at NordSec 2025
- HoneyGPT (Computer Networks 2026): currently being studied for integration
  ideas and comparison
- DecoyPOT (Computers & Security, Elsevier): under consideration as base paper
- WCAT module, local LLM integration, bug fixes: Simran Arora, CDAC Mohali
