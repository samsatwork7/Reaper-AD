"""
Discovery Engine - Real AD discovery implementation
"""

import socket
import dns.resolver
import dns.reversename
from typing import List, Dict, Any
import ldap3
from impacket.smbconnection import SMBConnection
import ipaddress

class DiscoveryEngine:
    def __init__(self, target: str, timeout: int = 10):
        self.target = target
        self.timeout = timeout
    
    def find_domain_controllers(self) -> List[str]:
        """Find domain controllers via DNS"""
        print(f"  [*] Discovering domain controllers...")
        dcs = []
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            # Try to extract domain from target
            domain = self.extract_domain_from_target()
            
            if domain:
                # Common DC DNS queries
                queries = [
                    f'_ldap._tcp.dc._msdcs.{domain}',
                    f'_kerberos._tcp.dc._msdcs.{domain}',
                    f'_ldap._tcp.{domain}',
                    f'gc._msdcs.{domain}',
                    f'dc.{domain}',
                    f'ad.{domain}',
                    f'dc01.{domain}',
                    f'dc02.{domain}'
                ]
                
                for query in queries:
                    try:
                        answers = resolver.resolve(query, 'SRV' if '_' in query else 'A')
                        for answer in answers:
                            if hasattr(answer, 'target'):
                                dc = str(answer.target).rstrip('.')
                                if dc not in dcs:
                                    dcs.append(dc)
                            else:
                                dc = str(answer)
                                if dc not in dcs:
                                    dcs.append(dc)
                    except:
                        continue
            
            # Also try the target itself
            if self.is_ip(self.target):
                # Try reverse DNS
                try:
                    rev_name = dns.reversename.from_address(self.target)
                    answers = resolver.resolve(rev_name, 'PTR')
                    for answer in answers:
                        hostname = str(answer).rstrip('.')
                        if 'dc' in hostname.lower() or 'domain' in hostname.lower():
                            dcs.append(hostname)
                except:
                    pass
            else:
                # Try A record
                try:
                    answers = resolver.resolve(self.target, 'A')
                    for answer in answers:
                        dcs.append(str(answer))
                except:
                    pass
        
        except Exception as e:
            print(f"  [!] DC discovery error: {e}")
        
        return dcs
    
    def extract_domain_from_target(self) -> str:
        """Extract domain name from target"""
        if self.is_ip(self.target):
            return None
        
        parts = self.target.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return None
    
    def is_ip(self, address: str) -> bool:
        """Check if string is an IP address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False
    
    def enumerate_users(self, limit: int = 100) -> List[str]:
        """Enumerate users via LDAP"""
        print(f"  [*] Enumerating users via LDAP...")
        users = []
        
        try:
            # Try anonymous LDAP bind
            server = ldap3.Server(self.target, port=389, get_info=ldap3.ALL, 
                                connect_timeout=self.timeout)
            conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS, 
                                  auto_bind=True, receive_timeout=self.timeout)
            
            if conn.bound:
                # Try to get domain from rootDSE
                domain = None
                conn.search('', '(objectClass=*)', attributes=['defaultNamingContext'])
                if conn.entries:
                    domain = str(conn.entries[0].defaultNamingContext)
                
                if domain:
                    # Search for users
                    search_filter = '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
                    conn.search(domain, search_filter, 
                              attributes=['sAMAccountName', 'userPrincipalName'],
                              size_limit=limit)
                    
                    for entry in conn.entries:
                        if hasattr(entry, 'sAMAccountName'):
                            username = str(entry.sAMAccountName)
                            if username not in users:
                                users.append(username)
                
                conn.unbind()
        
        except Exception as e:
            if "anonymous" not in str(e).lower():
                print(f"  [!] User enumeration error: {e}")
        
        return users
    
    def find_services(self) -> List[Dict[str, str]]:
        """Find services with SPNs"""
        print(f"  [*] Finding services with SPNs...")
        services = []
        
        try:
            server = ldap3.Server(self.target, port=389, get_info=ldap3.ALL, 
                                connect_timeout=self.timeout)
            conn = ldap3.Connection(server, authentication=ldap3.ANONYMOUS, 
                                  auto_bind=True, receive_timeout=self.timeout)
            
            if conn.bound:
                # Get domain
                domain = None
                conn.search('', '(objectClass=*)', attributes=['defaultNamingContext'])
                if conn.entries:
                    domain = str(conn.entries[0].defaultNamingContext)
                
                if domain:
                    # Search for service accounts
                    search_filter = '(&(objectClass=user)(servicePrincipalName=*))'
                    conn.search(domain, search_filter, 
                              attributes=['sAMAccountName', 'servicePrincipalName'])
                    
                    for entry in conn.entries:
                        if hasattr(entry, 'servicePrincipalName'):
                            username = str(entry.sAMAccountName)
                            for spn in entry.servicePrincipalName:
                                services.append({
                                    'username': username,
                                    'spn': str(spn)
                                })
                
                conn.unbind()
        
        except Exception as e:
            print(f"  [!] Service discovery error: {e}")
        
        return services
    
    def enumerate_shares(self) -> List[str]:
        """Enumerate SMB shares"""
        print(f"  [*] Enumerating SMB shares...")
        shares = []
        
        try:
            smb = SMBConnection(self.target, self.target, timeout=self.timeout)
            
            # Try null session
            try:
                smb.login('', '')
            except:
                # Try with guest
                try:
                    smb.login('guest', '')
                except:
                    return shares
            
            # List shares
            share_list = smb.listShares()
            for share in share_list:
                share_name = share['shi1_netname'][:-1]  # Remove trailing null
                if share_name not in ['IPC$', 'ADMIN$']:
                    shares.append(share_name)
            
            smb.logoff()
        
        except Exception as e:
            if "STATUS_LOGON_FAILURE" not in str(e):
                print(f"  [!] Share enumeration error: {e}")
        
        return shares
