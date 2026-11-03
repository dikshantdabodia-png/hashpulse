# ⚡ HASHPULSE
### Password Security & Vulnerability Analyzer (Web + CLI)

A dual-interface, zero-knowledge password security audit platform engineered for both web browsers (hosted directly on **GitHub Pages via `/docs`**) and terminal environments (**Kali Linux / Dev CLI**).

HashPulse goes beyond basic character rules by executing a **multi-tier attack audit**:
1. **Live Breach Intelligence**: Queries Have I Been Pwned's 800M+ leaked passwords via cryptographic **$k$-Anonymity** (zero plaintext transmission).
2. **Offline Pattern Modeling (`zxcvbn`)**: Identifies dictionary words, spatial keyboard walks (`qwerty`, `1qaz2wsx`), and leetspeak substitutions (`p@ssw0rd`).
3. **Hardware-Benchmarked Crack Matrix**: Calculates realistic time-to-crack against modern brute-force and GPU cracking clusters (RTX 4090 / Hashcat rigs).
4. **Local Wordlist Scanner**: In CLI mode, scan directly against local Kali wordlists (e.g., `/usr/share/wordlists/rockyou.txt`) using memory-efficient streaming.

---

## 🔒 Cryptographic Privacy Model ($k$-Anonymity)

Both the Web and CLI versions guarantee that your plaintext password **never touches any external server**:

```text
User Input: "Password123"
      │
      ▼
Local SHA-1 Hash Calculation:
"CBFDAC6008F9CAB4083784CBD1874F76618D2A97"
      │
      ├───────────────────────────────┐
      │ (First 5 Hex Chars)           │ (Remaining 35 Hex Chars)
      ▼                               ▼
Sent to HIBP API:               Kept in Local Memory:
GET /range/CBFDA                "C6008F9CAB4083784CBD1874F76618D2A97"
      │                               │
      ▼                               ▼
API returns ~500 hash suffixes ──▶ Exact match verified locally!
                                       │
                                       ▼
                       Flagged as Breached / Safe
```

---

## 📁 Repository Structure

```text
HASHPULSE/
├── docs/                       # Web application hosted by GitHub Pages
│   ├── index.html              # High-contrast minimalist web UI
│   ├── style.css               # Monochrome design system
│   └── script.js               # Web Crypto, HIBP k-Anonymity & zxcvbn engine
├── cli/                        # Terminal auditor for Kali Linux / Developers
│   ├── hashpulse.py            # CLI script with Rich dashboard & local wordlists
│   └── requirements.txt        # Optional CLI dependencies (zxcvbn, requests, rich)
└── README.md                   # Complete documentation
```

---

## 🐧 Running the CLI (Kali Linux / Terminal)

The CLI tool is located in `/cli` and works with zero setup (falls back to Python's standard library if optional packages are not installed).

### 1. Installation
```bash
git clone https://github.com/<your-username>/HashPulse.git
cd HashPulse/cli
pip install -r requirements.txt
```

### 2. Usage Examples

* **Secure Hidden Prompt (Recommended)**:
  ```bash
  python hashpulse.py
  # Enter password to audit (input hidden): ********
  ```

* **Direct Argument**:
  ```bash
  python hashpulse.py "P@ssw0rd2024!"
  ```

* **Scan Against Kali's `rockyou.txt`**:
  ```bash
  python hashpulse.py -w /usr/share/wordlists/rockyou.txt
  ```

* **Air-gapped / Offline Mode** (skips HIBP network request):
  ```bash
  python hashpulse.py --offline
  ```

---

## ⚡ Attack Scenario Benchmarks

| Attack Scenario | Hash Rate Profile | Attack Context |
| :--- | :--- | :--- |
| **Online Web Service** | `100 / sec` | Throttled / rate-limited endpoints, lockouts |
| **Offline Slow Hash** | `10,000 / sec` | Modern salted KDFs (bcrypt, Argon2, PBKDF2) |
| **Offline Fast Hash (Single GPU)** | `100 GH/s` | Leaked NTLM or MD5 cracked on an RTX 4090 |
| **Cracking Rig / Cluster** | `1 TH/s` | Dedicated 8x RTX 4090 Hashcat cluster |

---

## ⚖️ License

MIT License. Free for educational, personal, and commercial security audits.
