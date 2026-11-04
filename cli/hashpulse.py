#!/usr/bin/env python3
"""
HASHPULSE // CLI
Password Security & Vulnerability Analyzer for Linux / Kali / Terminal Environments.

Dual-layer audit:
  1. Have I Been Pwned (HIBP) k-Anonymity SHA-1 Breach Intelligence
  2. zxcvbn Markov Entropy, Spatial/Dictionary Patterns & Hardware Crack Matrix
  3. Optional local wordlist lookup (e.g. /usr/share/wordlists/rockyou.txt)
"""

import sys
import os
import argparse
import getpass
import hashlib
import math
import re
from typing import Dict, Any, Optional, Tuple

# Try importing rich for enhanced terminal UI; fallback to ANSI colors
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    HAS_RICH = True
    console = Console()
except ImportError:
    HAS_RICH = False

# Try importing requests for HIBP API; fallback to urllib
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

# Try importing zxcvbn; fallback to heuristic estimator
try:
    from zxcvbn import zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False


STRENGTH_LABELS = [
    "VERY WEAK",
    "WEAK",
    "FAIR",
    "STRONG",
    "VERY STRONG"
]


def format_crack_time(seconds: float) -> str:
    """Convert crack time in seconds to human-readable units."""
    if not math.isfinite(seconds) or seconds < 0:
        return "INSTANT (<1s)"
    if seconds < 1:
        return "INSTANT (<1 sec)"
    if seconds < 60:
        return f"{round(seconds)} seconds"
    if seconds < 3600:
        return f"{round(seconds / 60)} minutes"
    if seconds < 86400:
        return f"{round(seconds / 3600)} hours"
    if seconds < 31536000:
        return f"{round(seconds / 86400)} days"
    if seconds < 3153600000:
        return f"{round(seconds / 31536000)} years"
    if seconds < 315360000000:
        return f"{round(seconds / 3153600000)} centuries"
    centuries = seconds / 3153600000
    if centuries < 1e9:
        return f"{centuries:.2e} centuries"
    return "> 10^12 centuries"


def calculate_entropy_and_composition(password: str) -> Dict[str, Any]:
    """Calculate character set pool, Shannon entropy, and diversity rules."""
    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_number = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    no_repeats = not bool(re.search(r"(.)\1", password))

    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_number:
        pool += 10
    if has_symbol:
        pool += 33

    entropy = 0.0
    if pool > 0 and length > 0:
        entropy = length * (math.log(pool) / math.log(2))

    return {
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_number": has_number,
        "has_symbol": has_symbol,
        "no_repeats": no_repeats,
        "pool": pool,
        "entropy": round(entropy, 1)
    }


def check_hibp_k_anonymity(password: str, timeout: int = 5) -> Tuple[bool, int, str]:
    """
    Check Have I Been Pwned via k-Anonymity model.
    Sends only first 5 chars of SHA-1 hash; compares remainder locally.
    Returns: (is_breached, breach_count, status_message)
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"Add-Padding": "true", "User-Agent": "HashPulse-CLI-Auditor"}

    try:
        if HAS_REQUESTS:
            response = requests.get(url, headers=headers, timeout=timeout)
            if response.status_code != 200:
                return False, 0, f"HTTP Error {response.status_code}"
            text_data = response.text
        else:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                text_data = resp.read().decode("utf-8")

        for line in text_data.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == suffix:
                try:
                    count = int(parts[1].strip())
                except ValueError:
                    count = 1
                return True, count, "BREACHED"

        return False, 0, "SAFE (0 leaks found)"

    except Exception as exc:
        return False, 0, f"OFFLINE ({type(exc).__name__})"


def scan_local_wordlist(password: str, wordlist_path: str) -> Tuple[bool, Optional[str]]:
    """
    Optional: Scan a local wordlist file (like rockyou.txt) using memory-efficient streaming.
    """
    if not os.path.exists(wordlist_path):
        return False, f"File not found: {wordlist_path}"

    target = password.strip()
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_idx, line in enumerate(f, 1):
                if line.rstrip("\r\n") == target:
                    return True, f"Found at line #{line_idx:,}"
        return False, "Not found in local wordlist"
    except Exception as err:
        return False, f"Error reading wordlist: {err}"


def run_audit(password: str, offline: bool = False, wordlist: Optional[str] = None):
    """Execute the full HashPulse audit."""
    if not password:
        print("[!] Error: No password provided.")
        return

    # 1. Composition & Entropy
    comp = calculate_entropy_and_composition(password)

    # 2. zxcvbn Base Model
    if HAS_ZXCVBN:
        z_res = zxcvbn(password)
        score = z_res.get("score", 0)
        guesses = max(z_res.get("guesses", 1), 1)
        feedback = z_res.get("feedback", {})
        sequence = z_res.get("sequence", [])
    else:
        # Heuristic fallback if zxcvbn is not installed
        combos = (comp["pool"] or 10) ** comp["length"]
        guesses = combos
        if comp["entropy"] < 28:
            score = 0
        elif comp["entropy"] < 40:
            score = 1
        elif comp["entropy"] < 55:
            score = 2
        elif comp["entropy"] < 70:
            score = 3
        else:
            score = 4
        feedback = {
            "warning": "Install 'zxcvbn' python package for deep spatial/dictionary analysis.",
            "suggestions": ["Add more length and mix uppercase, lowercase, numbers, and symbols."]
        }
        sequence = []

    # 3. HIBP Online Check
    hibp_breached = False
    hibp_count = 0
    hibp_status = "SKIPPED (Offline mode)"

    if not offline:
        hibp_breached, hibp_count, hibp_status = check_hibp_k_anonymity(password)

    # 4. Local Wordlist Check (if requested)
    local_wordlist_hit = False
    local_wordlist_msg = None
    if wordlist:
        local_wordlist_hit, local_wordlist_msg = scan_local_wordlist(password, wordlist)

    # 5. Crack Times (Attacker averages 50% search space)
    target_guesses = guesses * 0.5
    if hibp_breached or local_wordlist_hit:
        t_online = "INSTANT (In Wordlists)"
        t_slow = "INSTANT (In Wordlists)"
        t_fast = "INSTANT (In Wordlists)"
        t_cluster = "INSTANT (In Wordlists)"
    else:
        t_online = format_crack_time(target_guesses / 100)
        t_slow = format_crack_time(target_guesses / 10000)
        t_fast = format_crack_time(target_guesses / 1e11)  # 100 GH/s (RTX 4090)
        t_cluster = format_crack_time(target_guesses / 1e12)  # 1 TH/s (8x 4090)

    # =========================================================================
    # DISPLAY OUTPUT
    # =========================================================================
    if HAS_RICH:
        render_rich_output(
            password=password,
            comp=comp,
            score=score,
            guesses=guesses,
            hibp_breached=hibp_breached,
            hibp_count=hibp_count,
            hibp_status=hibp_status,
            local_wordlist_hit=local_wordlist_hit,
            local_wordlist_msg=local_wordlist_msg,
            wordlist_path=wordlist,
            t_online=t_online,
            t_slow=t_slow,
            t_fast=t_fast,
            t_cluster=t_cluster,
            feedback=feedback,
            sequence=sequence
        )
    else:
        render_plain_output(
            password=password,
            comp=comp,
            score=score,
            guesses=guesses,
            hibp_breached=hibp_breached,
            hibp_count=hibp_count,
            hibp_status=hibp_status,
            local_wordlist_hit=local_wordlist_hit,
            local_wordlist_msg=local_wordlist_msg,
            wordlist_path=wordlist,
            t_online=t_online,
            t_slow=t_slow,
            t_fast=t_fast,
            t_cluster=t_cluster,
            feedback=feedback,
            sequence=sequence
        )


def render_rich_output(password, comp, score, guesses, hibp_breached, hibp_count,
                       hibp_status, local_wordlist_hit, local_wordlist_msg, wordlist_path,
                       t_online, t_slow, t_fast, t_cluster, feedback, sequence):
    """Render sleek monochrome/cyber dashboard with rich."""
    console.print()
    console.rule("[bold white]HASHPULSE // PASSWORD SECURITY AUDITOR[/bold white]")

    # Breach Alert Banner if breached
    if hibp_breached or local_wordlist_hit:
        alert_msg = ""
        if hibp_breached:
            alert_msg += f"• FOUND IN PUBLIC BREACHES: Seen {hibp_count:,} times in known breach dumps!\n"
        if local_wordlist_hit:
            alert_msg += f"• FOUND IN LOCAL WORDLIST: {local_wordlist_msg} ({wordlist_path})\n"
        alert_msg += "Attackers utilizing dictionary / rainbow attacks will crack this password IMMEDIATELY."
        console.print(Panel(alert_msg.strip(), title="[bold white on red] ALERT: PWNED / COMPROMISED [/bold white on red]", border_style="red"))

    # Quick Metrics Table
    status_label = STRENGTH_LABELS[score]
    if hibp_breached or local_wordlist_hit:
        status_label = "[bold red]COMPROMISED (IN WORDLIST)[/bold red]"
    else:
        status_label = f"[bold white]{status_label} (Score: {score}/4)[/bold white]"

    summary_table = Table(box=None, padding=(0, 2))
    summary_table.add_column("METRIC", style="bold white")
    summary_table.add_column("VALUE", style="bright_white")
    summary_table.add_column("METRIC", style="bold white")
    summary_table.add_column("VALUE", style="bright_white")

    summary_table.add_row("Password Length", f"{comp['length']} characters", "HIBP Status", f"[bold]{hibp_status}[/bold]")
    summary_table.add_row("Raw Entropy", f"{comp['entropy']} bits", "Search Space", f"{guesses:.2e}" if guesses >= 1e9 else f"{guesses:,}")
    summary_table.add_row("Evaluation", status_label, "Pool Diversity", f"{comp['pool']} possible chars")

    console.print(Panel(summary_table, title="[bold white]AUDIT OVERVIEW[/bold white]", border_style="bright_black"))

    # Composition Checklist
    comp_text = (
        f"[{'green' if comp['has_lower'] else 'red'}][{'X' if comp['has_lower'] else ' '}] Lowercase (a-z)[/]  |  "
        f"[{'green' if comp['has_upper'] else 'red'}][{'X' if comp['has_upper'] else ' '}] Uppercase (A-Z)[/]  |  "
        f"[{'green' if comp['has_number'] else 'red'}][{'X' if comp['has_number'] else ' '}] Digits (0-9)[/]  |  "
        f"[{'green' if comp['has_symbol'] else 'red'}][{'X' if comp['has_symbol'] else ' '}] Symbols[/]  |  "
        f"[{'green' if comp['length'] >= 12 else 'red'}][{'X' if comp['length'] >= 12 else ' '}] Length >= 12[/]  |  "
        f"[{'green' if comp['no_repeats'] else 'red'}][{'X' if comp['no_repeats'] else ' '}] No Repeats[/]"
    )
    console.print(Panel(comp_text, title="[bold white]CHARACTER SET DIVERSITY[/bold white]", border_style="bright_black"))

    # Hardware Crack Matrix Table
    crack_table = Table(title="ESTIMATED TIME TO CRACK BY ATTACK SCENARIO", title_style="bold white", border_style="bright_black")
    crack_table.add_column("Attack Vector", style="white")
    crack_table.add_column("Hardware / Rate", style="bright_black")
    crack_table.add_column("Estimated Time", style="bold bright_white")

    crack_table.add_row("Online Web Service", "100 guesses/sec (rate-limited / lockout)", t_online)
    crack_table.add_row("Offline Slow Hash", "10,000 / sec (bcrypt, Argon2, PBKDF2)", t_slow)
    crack_table.add_row("Offline Fast Hash (Single GPU)", "100 GH/s (RTX 4090 on NTLM/MD5)", t_fast)
    crack_table.add_row("Cracking Rig / Cluster", "1 TH/s (8x RTX 4090 Hashcat cluster)", t_cluster)

    console.print(crack_table)

    # Patterns & Feedback
    pattern_lines = []
    if sequence:
        for item in sequence:
            pat = item.get("pattern", "").upper()
            tok = item.get("token", "")
            dname = item.get("dictionary_name", "")
            details = []
            if dname:
                details.append(dname)
            if item.get("l33t"):
                details.append("leetspeak")
            if item.get("reversed"):
                details.append("reversed")
            detail_str = f" ({', '.join(details)})" if details else ""
            pattern_lines.append(f"  • {pat}: '{tok}'{detail_str}")

    feedback_lines = []
    warning = feedback.get("warning")
    if warning:
        feedback_lines.append(f"[bold yellow]Warning:[/] {warning}")
    for sug in feedback.get("suggestions", []):
        feedback_lines.append(f"[bold cyan]Tip:[/] {sug}")

    analysis_content = ""
    if pattern_lines:
        analysis_content += "[bold white]Detected Patterns & Sequences:[/] \n" + "\n".join(pattern_lines) + "\n\n"
    if feedback_lines:
        analysis_content += "[bold white]Hardening Suggestions:[/] \n" + "\n".join(feedback_lines)
    if not analysis_content:
        analysis_content = "No obvious dictionary words or spatial walks detected. Password exhibits good entropy."

    console.print(Panel(analysis_content.strip(), title="[bold white]PATTERN & DICTIONARY BREAKDOWN[/bold white]", border_style="bright_black"))
    console.print("[dim white]HashPulse // Zero-Knowledge Client Execution • SHA-1 k-Anonymity Verified[/dim white]\n")


def render_plain_output(password, comp, score, guesses, hibp_breached, hibp_count,
                        hibp_status, local_wordlist_hit, local_wordlist_msg, wordlist_path,
                        t_online, t_slow, t_fast, t_cluster, feedback, sequence):
    """Fallback plain ANSI renderer when rich is not installed."""
    print("\n" + "=" * 65)
    print("           HASHPULSE // PASSWORD SECURITY AUDITOR")
    print("=" * 65)

    if hibp_breached or local_wordlist_hit:
        print("\n[!] ALERT: PWNED / COMPROMISED")
        if hibp_breached:
            print(f"    • Found in HIBP database ({hibp_count:,} breach appearances)!")
        if local_wordlist_hit:
            print(f"    • Found in local wordlist: {local_wordlist_msg}")
        print("    Attackers with wordlists or rainbow tables can crack this INSTANTLY.\n")

    eval_label = STRENGTH_LABELS[score]
    if hibp_breached or local_wordlist_hit:
        eval_label = "COMPROMISED (IN WORDLIST)"

    print(f"Evaluation:     {eval_label} (Score: {score}/4)")
    print(f"Length:         {comp['length']} chars")
    print(f"Entropy:        {comp['entropy']} bits")
    print(f"HIBP Status:    {hibp_status}")
    print(f"Search Space:   {guesses:.2e}" if guesses >= 1e9 else f"Search Space:   {guesses:,}")
    print("-" * 65)
    print("CHARACTER SET DIVERSITY:")
    print(f"  [{'X' if comp['has_lower'] else ' '}] Lowercase (a-z)")
    print(f"  [{'X' if comp['has_upper'] else ' '}] Uppercase (A-Z)")
    print(f"  [{'X' if comp['has_number'] else ' '}] Digits (0-9)")
    print(f"  [{'X' if comp['has_symbol'] else ' '}] Symbols (!@#$...)")
    print(f"  [{'X' if comp['length'] >= 12 else ' '}] Length >= 12")
    print(f"  [{'X' if comp['no_repeats'] else ' '}] No Consecutive Repeats")
    print("-" * 65)
    print("ESTIMATED TIME TO CRACK:")
    print(f"  Online Web Service (100/s):        {t_online}")
    print(f"  Offline Slow Hash (10,000/s):      {t_slow}")
    print(f"  Offline Fast Hash (RTX 4090 100G): {t_fast}")
    print(f"  Cracking Rig (8x 4090 1 TH/s):     {t_cluster}")
    print("-" * 65)
    if feedback.get("warning"):
        print(f"Warning: {feedback.get('warning')}")
    for sug in feedback.get("suggestions", []):
        print(f"Tip:     {sug}")
    print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="HashPulse: Dual-layer password security & breach intelligence analyzer."
    )
    parser.add_argument(
        "password",
        nargs="?",
        help="Password to evaluate (leave empty to enter securely via hidden prompt)"
    )
    parser.add_argument(
        "-p", "--password-input",
        dest="pwd_flag",
        help="Password string passed via flag"
    )
    parser.add_argument(
        "-w", "--wordlist",
        help="Path to a local wordlist file to scan (e.g., /usr/share/wordlists/rockyou.txt)"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run 100% offline (skip Have I Been Pwned API query)"
    )

    args = parser.parse_args()

    # Determine password
    target_pwd = args.password or args.pwd_flag
    if not target_pwd:
        try:
            target_pwd = getpass.getpass("Enter password to audit (input hidden): ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    run_audit(target_pwd, offline=args.offline, wordlist=args.wordlist)


if __name__ == "__main__":
    main()
