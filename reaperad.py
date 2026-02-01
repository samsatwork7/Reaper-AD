#!/usr/bin/env python3
"""
ReaperAD v3.0 - COMPLETE AD Exploitation Framework
Version with compatible imports for all Impacket versions
"""

import sys
import argparse
import logging
import json
import time
import random
import hashlib
import socket
import struct
import os
import base64
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock, Semaphore
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from collections import defaultdict

# ============ DYNAMIC IMPORTS WITH FALLBACKS ============

# Initialize colorama first (for error messages)
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class DummyColors:
        def __getattr__(self, name):
            return ''
    Fore = Style = DummyColors()

def check_imports():
    """Check and import all required libraries with helpful error messages"""
    missing = []
    
    # Impacket core
    try:
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AS_REQ, TGS_REP
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5.types import Principal, KerberosTime
        globals().update({
            'constants': constants,
            'AS_REQ': AS_REQ,
            'TGS_REP': TGS_REP,
            'getKerberosTGT': getKerberosTGT,
            'getKerberosTGS': getKerberosTGS,
            'Principal': Principal,
            'KerberosTime': KerberosTime
        })
    except ImportError as e:
        missing.append(f"impacket.krb5 - {e}")
    
    # SMB
    try:
        from impacket.smbconnection import SMBConnection
        globals()['SMBConnection'] = SMBConnection
    except ImportError:
        missing.append("impacket.smbconnection")
    
    # NTLM
    try:
        from impacket.ntlm import compute_lmhash, compute_nthash
        globals().update({
            'compute_lmhash': compute_lmhash,
            'compute_nthash': compute_nthash
        })
    except ImportError:
        missing.append("impacket.ntlm")
    
    # DCE/RPC modules
    try:
        from impacket.dcerpc.v5 import transport, samr, lsad
        globals().update({
            'transport': transport,
            'samr': samr,
            'lsad': lsad
        })
    except ImportError:
        missing.append("impacket.dcerpc.v5")
    
    # Secrets dump
    try:
        from impacket.examples.secretsdump import RemoteOperations, NTDSHashes
        globals().update({
            'RemoteOperations': RemoteOperations,
            'NTDSHashes': NTDSHashes
        })
    except ImportError:
        missing.append("impacket.examples.secretsdump")
    
    # LDAP3
    try:
        import ldap3
        globals()['ldap3'] = ldap3
    except ImportError:
        missing.append("ldap3")
    
    # Cryptodome
    try:
        from Cryptodome.Hash import MD4
        globals()['MD4'] = MD4
    except ImportError:
        missing.append("pycryptodome")
    
    # DNS
    try:
        import dns.resolver
        globals()['dns'] = dns
    except ImportError:
        missing.append("dnspython")
    
    # Rich (optional)
    try:
        from rich.console import Console
        from rich.table import Table
        globals().update({
            'Console': Console,
            'Table': Table,
            'RICH_AVAILABLE': True
        })
    except ImportError:
        globals()['RICH_AVAILABLE'] = False
    
    if missing:
        print(f"{Fore.RED}[ERROR] Missing dependencies:{Style.RESET_ALL}")
        for dep in missing:
            print(f"  - {dep}")
        print(f"\n{Fore.YELLOW}[INFO] Install with:{Style.RESET_ALL}")
        print("  pip install impacket ldap3 pycryptodome dnspython colorama")
        return False
    
    return True

# Check imports before proceeding
if not check_imports():
    sys.exit(1)

# ============ MAIN CODE STARTS HERE ============

class ReaperAD:
    def __init__(self, target, username=None, password=None, domain=None, 
                 timeout=10, threads=5, stealth=False, output_dir='./reaper_output'):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.timeout = timeout
        self.max_threads = threads
        self.stealth = stealth
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        self.results = {
            'metadata': {
                'target': target,
                'domain': domain,
                'start_time': datetime.now().isoformat(),
                'args': {'username': username, 'stealth': stealth}
            },
            'vulnerabilities': [],
            'compromised_accounts': [],
            'extracted_data': {},
            'persistence': [],
            'attack_timeline': []
        }
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.5 if stealth else 0.1
        
        # Common passwords
        self.common_passwords = [
            'Password123', 'Welcome1', 'P@ssw0rd', 'Spring2024!',
            'Summer2024!', 'Winter2024!', 'Fall2024!', 'Company123',
            'Corp2024!', 'Admin123!', 'Qwerty123!', 'Passw0rd',
            'Changeme123', 'Secret123', 'Aa123456', '1qaz2wsx',
            'P@$$w0rd', 'Summer2023!', 'Winter2023!', 'Admin@123'
        ]
    
    def print_banner(self):
        """Print tool banner"""
        banner = f"""
{Fore.RED}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                R E A P E R A D   v3.0                        ║
║                                                              ║
║        Active Directory Exploitation Framework               ║
║                                                              ║
║        WARNING: For authorized testing only!                 ║
║        Unauthorized use is illegal and unethical.            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
Target: {self.target}
Domain: {self.domain or 'Not specified'}
Mode: {'Stealth' if self.stealth else 'Normal'}
Threads: {self.max_threads}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        print(banner)
    
    def check_ldap_anonymous(self):
        """Check LDAP anonymous bind"""
        print(f"{Fore.CYAN}[*] Checking LDAP anonymous bind...{Style.RESET_ALL}")
        try:
            server = ldap3.Server(self.target, port=389, get_info=ldap3.ALL, 
                                connect_timeout=self.timeout)
            conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS, 
                                  auto_bind=True, receive_timeout=self.timeout)
            
            if conn.bound:
                print(f"{Fore.GREEN}[+] LDAP anonymous bind successful!{Style.RESET_ALL}")
                conn.unbind()
                return True
                
        except Exception as e:
            print(f"{Fore.YELLOW}[!] LDAP anonymous bind failed: {e}{Style.RESET_ALL}")
        
        return False
    
    def authenticate_smb(self, username, password):
        """Test SMB authentication"""
        try:
            smb = SMBConnection(self.target, self.target, timeout=self.timeout)
            smb.login(username, password, self.domain or '')
            smb.logoff()
            return True
        except Exception:
            return False
    
    def run_discovery(self):
        """Run discovery phase"""
        print(f"\n{Fore.CYAN}[*] Starting discovery phase{Style.RESET_ALL}")
        
        # Check LDAP
        ldap_result = self.check_ldap_anonymous()
        self.results['vulnerabilities'].append({
            'type': 'LDAP Anonymous Bind',
            'severity': 'High',
            'found': ldap_result,
            'timestamp': datetime.now().isoformat()
        })
        
        # Try SMB null session
        print(f"{Fore.CYAN}[*] Checking SMB null session...{Style.RESET_ALL}")
        try:
            smb = SMBConnection(self.target, self.target, timeout=self.timeout)
            smb.login('', '')
            print(f"{Fore.GREEN}[+] SMB null session successful!{Style.RESET_ALL}")
            smb.logoff()
            self.results['vulnerabilities'].append({
                'type': 'SMB Null Session',
                'severity': 'Medium',
                'found': True,
                'timestamp': datetime.now().isoformat()
            })
        except Exception:
            print(f"{Fore.YELLOW}[!] SMB null session failed{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[✓] Discovery phase completed{Style.RESET_ALL}")
    
    def run_credential_attack(self):
        """Run credential attacks"""
        print(f"\n{Fore.CYAN}[*] Starting credential attacks{Style.RESET_ALL}")
        
        if not self.username or not self.password:
            print(f"{Fore.YELLOW}[!] No credentials provided, skipping authenticated attacks{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Testing provided credentials...{Style.RESET_ALL}")
        
        # Test SMB auth
        if self.authenticate_smb(self.username, self.password):
            print(f"{Fore.GREEN}[+] Credentials valid via SMB!{Style.RESET_ALL}")
            self.results['compromised_accounts'].append({
                'username': self.username,
                'password': self.password,
                'method': 'Provided',
                'timestamp': datetime.now().isoformat()
            })
        else:
            print(f"{Fore.RED}[-] Credentials invalid{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[✓] Credential phase completed{Style.RESET_ALL}")
    
    def generate_report(self):
        """Generate report"""
        self.results['metadata']['end_time'] = datetime.now().isoformat()
        
        report_file = self.output_dir / f"reaperad_report_{self.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}                    EXECUTION SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}[STATISTICS]{Style.RESET_ALL}")
        print(f"  Target: {self.target}")
        print(f"  Vulnerabilities Found: {len(self.results['vulnerabilities'])}")
        print(f"  Compromised Accounts: {len(self.results['compromised_accounts'])}")
        
        if self.results['vulnerabilities']:
            print(f"\n{Fore.WHITE}[VULNERABILITIES]{Style.RESET_ALL}")
            for vuln in self.results['vulnerabilities']:
                if vuln.get('found'):
                    status = f"{Fore.GREEN}✓{Style.RESET_ALL}"
                else:
                    status = f"{Fore.RED}✗{Style.RESET_ALL}"
                print(f"  {status} {vuln.get('type')} ({vuln.get('severity')})")
        
        if self.results['compromised_accounts']:
            print(f"\n{Fore.WHITE}[COMPROMISED ACCOUNTS]{Style.RESET_ALL}")
            for acc in self.results['compromised_accounts']:
                print(f"  • {acc.get('username')}")
        
        print(f"\n{Fore.GREEN}[+] Report saved to: {report_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] For authorized testing only!{Style.RESET_ALL}")
    
    def run(self):
        """Main execution"""
        self.print_banner()
        
        # Ask for confirmation
        response = input(f"\n{Fore.YELLOW}[?] Continue with attack? (y/N): {Style.RESET_ALL}")
        if response.lower() != 'y':
            print(f"{Fore.YELLOW}[!] Execution cancelled{Style.RESET_ALL}")
            return
        
        # Run phases
        try:
            self.run_discovery()
            self.run_credential_attack()
            self.generate_report()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
            self.generate_report()
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description='ReaperAD v3.0 - Active Directory Exploitation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Fore.YELLOW}Examples:{Style.RESET_ALL}
  %(prog)s dc.corp.local
  %(prog)s 192.168.1.10 -d CORP -u admin -p "Password123"
  %(prog)s target.local --stealth --threads 3
  %(prog)s dc.example.com --output ./results

{Fore.RED}Warning: For authorized testing only!{Style.RESET_ALL}
        '''
    )
    
    parser.add_argument('target', help='Target Domain Controller')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('--stealth', action='store_true', help='Stealth mode (slower)')
    parser.add_argument('--threads', type=int, default=5, help='Concurrent threads')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('--output', type=str, default='./reaper_output', 
                       help='Output directory for results')
    
    args = parser.parse_args()
    
    try:
        reaper = ReaperAD(
            target=args.target,
            username=args.username,
            password=args.password,
            domain=args.domain,
            timeout=args.timeout,
            threads=args.threads,
            stealth=args.stealth,
            output_dir=args.output
        )
        
        reaper.run()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()
