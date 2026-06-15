#!/usr/bin/env python3
# =============================================================================
# HoneyAI Stats Collector — Consolidated Metrics Bridge
# Parses events.json and generates statistics for blog reports and dashboard.
# =============================================================================
import os
import sys
import json
import re
from datetime import datetime, timedelta
from collections import Counter

CVE_MAP = {
    "/wp-login": {"cve": "WordPress", "mitre": "T1078", "tactic": "Initial Access"},
    "/wp-admin": {"cve": "WordPress", "mitre": "T1078", "tactic": "Initial Access"},
    "/xmlrpc": {"cve": "CVE-2020-28037", "mitre": "T1190", "tactic": "Initial Access"},
    "/.env": {"cve": "CWE-200", "mitre": "T1552.001", "tactic": "Credential Access"},
    "/.git": {"cve": "CWE-538", "mitre": "T1552.004", "tactic": "Credential Access"},
    "/actuator": {"cve": "CVE-2022-22947", "mitre": "T1190", "tactic": "Initial Access"},
    "/solr": {"cve": "CVE-2021-44228", "mitre": "T1190", "tactic": "Initial Access"},
    "/sdk/weblanguage": {"cve": "CVE-2021-36260", "mitre": "T1190", "tactic": "Initial Access"},
    "/cgi-bin": {"cve": "CVE-2014-6271", "mitre": "T1190", "tactic": "Initial Access"},
    "/phpunit": {"cve": "CVE-2017-9841", "mitre": "T1190", "tactic": "Initial Access"},
    "/phpmyadmin": {"cve": "CVE-2019-12922", "mitre": "T1190", "tactic": "Initial Access"},
    "/shell": {"cve": "WebShell", "mitre": "T1505.003", "tactic": "Persistence"},
    "/boaform": {"cve": "CVE-2023-22960", "mitre": "T1190", "tactic": "Initial Access"},
    "/telescope": {"cve": "Laravel-Debug", "mitre": "T1190", "tactic": "Initial Access"},
    "/remote/fgt_lang": {"cve": "CVE-2022-40684", "mitre": "T1190", "tactic": "Initial Access"},
    "/console": {"cve": "CVE-2022-22963", "mitre": "T1190", "tactic": "Initial Access"},
    "/login": {"cve": "Brute-Force", "mitre": "T1110", "tactic": "Credential Access"},
    "/admin": {"cve": "Admin-Probe", "mitre": "T1595.002", "tactic": "Reconnaissance"},
    "/config": {"cve": "CWE-200", "mitre": "T1552", "tactic": "Credential Access"},
}

def load_events(events_path):
    if not os.path.exists(events_path):
        return []
    
    events = []
    with open(events_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except:
                pass
    return events

def filter_last_24h(events):
    now = datetime.utcnow()
    cutoff = now - timedelta(hours=24)
    filtered = []
    for e in events:
        ts_str = e.get('timestamp')
        if not ts_str:
            continue
        try:
            ts_str_clean = ts_str.rstrip('Z')
            ts_parts = ts_str_clean.split('.')
            dt = datetime.strptime(ts_parts[0], "%Y-%m-%dT%H:%M:%S")
            if len(ts_parts) > 1:
                ms = int(ts_parts[1][:6].ljust(6, '0')) / 1000000.0
                dt = dt + timedelta(seconds=ms)
            
            if dt >= cutoff:
                filtered.append(e)
        except:
            pass
    return filtered

def filter_today(events):
    # Filter based on local timezone date (since dashboard logs "today")
    today_str = datetime.now().strftime("%Y-%m-%d")
    filtered = []
    for e in events:
        ts_str = e.get('timestamp')
        if not ts_str:
            continue
        if ts_str.startswith(today_str):
            filtered.append(e)
    return filtered

def filter_date(events, date_str):
    filtered = []
    for e in events:
        ts_str = e.get('timestamp')
        if not ts_str:
            continue
        if ts_str.startswith(date_str):
            filtered.append(e)
    return filtered

def main():
    events_path = sys.argv[1] if len(sys.argv) > 1 else "./logs/events.json"
    mode = sys.argv[2] if len(sys.argv) > 2 else "last_24h" # "last_24h", "today", or "YYYY-MM-DD"
    
    all_events = load_events(events_path)
    
    if re.match(r'^\d{4}-\d{2}-\d{2}$', mode):
        events = filter_date(all_events, mode)
    elif mode == "today":
        events = filter_today(all_events)
    else:
        events = filter_last_24h(all_events)
    
    # ── Basic Counters ──────────────────────────────────────────────────────
    ssh_connections = 0
    ssh_logins = 0
    ssh_commands = []
    ssh_ips = set()
    ssh_passwords = []
    ssh_credentials_list = []
    
    oc_events = 0
    oc_ips = set()
    oc_commands = []
    
    galah_requests = 0
    galah_ips = set()
    galah_paths = []
    galah_agents = []
    
    # Detailed stats for TTY & CVE
    tty_commands = []
    tty_counts = Counter()
    cve_hits = []
    mitre_tactics = Counter()
    path_counts = Counter()
    path_ips = {}
    
    all_ips = []
    
    # Operation Spine (Backfire scans)
    backfire_scans = 0
    backfire_ips = set()
    backfire_ports_tally = Counter()
    backfire_targets = []
    
    for e in events:
        proto = e.get('protocol')
        ip = e.get('ip')
        ts = e.get('timestamp', '')
        # Format HH:MM for recent lists
        time_str = ts[11:16] if len(ts) > 16 else ts
        
        if not ip or ip.startswith('127.') or ip.startswith('192.168.') or ip == '::1' or ip == 'localhost':
            continue
            
        all_ips.append(ip)
        
        if proto == 'ssh':
            ssh_connections += 1
            ssh_ips.add(ip)
            
            # Auth attempts
            if 'username' in e and ('password' in e or 'password_hash' in e or 'auth_method' in e):
                ssh_logins += 1
                u = e.get('username', '')
                p = e.get('password')
                p_hash = e.get('password_hash')
                auth_method = e.get('auth_method', 'password')
                
                if p is not None:
                    if p and p != '(key)':
                        ssh_passwords.append(p)
                    ssh_credentials_list.append(f"{u}:{p}")
                else:
                    if auth_method == 'password':
                        p_disp = p_hash if p_hash else '***'
                        ssh_passwords.append(p_disp)
                    else:
                        p_disp = f"({auth_method})"
                    ssh_credentials_list.append(f"{u}:{p_disp}")
            
            # Commands executed
            if 'command' in e:
                cmd = e.get('command')
                if cmd:
                    ssh_commands.append(cmd)
                    tty_counts[cmd] += 1
                    tty_commands.append({"cmd": cmd, "ip": ip, "time": time_str})
                    
        elif proto == 'tarpit':
            ssh_connections += 1
            ssh_ips.add(ip)
            
        elif proto == 'http':
            galah_requests += 1
            galah_ips.add(ip)
            
            path = e.get('path', '')
            if path:
                galah_paths.append(path)
                path_counts[path] += 1
                path_ips.setdefault(path, set()).add(ip)
                
                # Check against CVE map
                for pat, info in CVE_MAP.items():
                    if pat in path.lower():
                        cve_hits.append({
                            "path": path,
                            "ip": ip,
                            "cve": info["cve"],
                            "mitre": info["mitre"],
                            "tactic": info["tactic"]
                        })
                        mitre_tactics[info["tactic"]] += 1
                        break
                        
            agent = e.get('user_agent')
            if agent:
                galah_agents.append(agent)
                
        elif proto == 'backfire':
            backfire_scans += 1
            backfire_ips.add(ip)
            open_ports = e.get('open_ports', [])
            for port in open_ports:
                backfire_ports_tally[port] += 1
            backfire_targets.append({
                "ip": ip,
                "rdns": e.get('reverse_dns', ''),
                "ports": open_ports,
                "time": time_str
            })
            
        elif proto in ['ftp', 'telnet', 'smtp', 'mysql', 'redis', 'git', 'vnc', 'rdp']:
            oc_events += 1
            oc_ips.add(ip)
            
            # Treat TCP inputs as commands/activity
            if 'input' in e:
                inp = e.get('input')
                if inp:
                    oc_commands.append(f"[{proto}] {inp}")
                    
    # Helpers for top lists
    def get_top_items(items, limit=5):
        counts = Counter(items)
        return [item for item, _ in counts.most_common(limit)]
        
    def get_top_counts(items, limit=15):
        counts = Counter(items)
        return [{"cred": item, "count": count} for item, count in counts.most_common(limit)]

    top_ips = get_top_items(all_ips, 30) # get up to 30 for dashboard
    top_commands = get_top_items(ssh_commands, 5)
    top_passwords = get_top_items(ssh_passwords, 5)
    galah_top_paths = get_top_items(galah_paths, 5)
    galah_top_agents = get_top_items(galah_agents, 5)
    
    # Funny passwords
    funny_passwords = [p for p in ssh_passwords if not p.isdigit() and len(p) > 4]
    funny_pass = get_top_items(funny_passwords, 5)
    
    # Funny commands
    funny_cmds_patterns = re.compile(r'miner|bitcoin|wget|chmod|curl|/etc/passwd|uname|id$|whoami', re.IGNORECASE)
    funny_commands = [c for c in ssh_commands if funny_cmds_patterns.search(c)]
    funny_cmds = list(set(funny_commands))[:5]
    
    # Target files accessed
    file_patterns = re.compile(r'(wallet\.dat|passwords?\.txt|id_rsa|\.aws/credentials|\.env|db.dump|backup\.sql|config\.json)', re.IGNORECASE)
    files_accessed = [c for c in ssh_commands if file_patterns.search(c)]
    files_acc = list(set(files_accessed))[:5]
    
    # Dashboard TTY Replay Top commands
    top_tty_cmds = [{"cmd": c, "count": n} for c, n in tty_counts.most_common(20)]
    recent_tty_cmds = tty_commands[-15:][::-1]
    
    # CVE and MITRE
    top_paths_cve = [{"path": p, "count": c, "ips": len(path_ips.get(p, set()))} for p, c in path_counts.most_common(15)]
    seen_cves = set()
    cve_dedup = []
    for h in cve_hits:
        k = h["cve"] + h["path"]
        if k not in seen_cves:
            seen_cves.add(k)
            cve_dedup.append(h)
    mitre_summary = [{"tactic": t, "count": c} for t, c in mitre_tactics.most_common()]
    
    stats = {
        "ssh_connections": ssh_connections,
        "ssh_logins": ssh_logins,
        "ssh_commands": len(ssh_commands),
        "ssh_ips": len(ssh_ips),
        "ssh_ips_list": top_ips, # Top IPs list for dashboard
        "ssh_credentials": get_top_counts(ssh_credentials_list, 15), # Credentials for dashboard
        "opencanary_events": oc_events,
        "opencanary_ips": len(oc_ips),
        "galah_requests": galah_requests,
        "galah_ips": len(galah_ips),
        "backfire_scans": backfire_scans,
        "backfire_ips": len(backfire_ips),
        "backfire_ports_tally": [{"port": port, "count": count} for port, count in backfire_ports_tally.most_common()],
        "backfire_targets": backfire_targets,
        "top_ips": top_ips[:5],
        "top_commands": top_commands,
        "top_passwords": top_passwords,
        "funny_passwords": funny_pass,
        "funny_commands": funny_cmds,
        "honeypot_files_accessed": files_acc,
        "galah_top_paths": galah_top_paths,
        "galah_top_agents": galah_top_agents,
        # Dashboard TTY & CVE section
        "tty_replay": {
            "top_commands": top_tty_cmds,
            "recent": recent_tty_cmds
        },
        "cve_scanner": {
            "top_paths": top_paths_cve,
            "cve_detections": cve_dedup[:20],
            "mitre_tactics": mitre_summary
        }
    }
    
    print(json.dumps(stats, indent=2))

if __name__ == "__main__":
    main()
