"""
Privilege Escalation Engine
"""

from typing import List, Dict, Any
import ldap3

class PrivilegeEscalator:
    def __init__(self, target: str, username: str = None, password: str = None, 
                 domain: str = None, hashes: str = None):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.hashes = hashes
    
    def find_escalation_paths(self, credential: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find privilege escalation paths"""
        print(f"  [*] Looking for escalation paths...")
        paths = []
        
        username = credential.get('username')
        password = credential.get('password')
        hash_val = credential.get('hash')
        
        if not username or (not password and not hash_val):
            return paths
        
        try:
            # Try to authenticate with the credential
            server = ldap3.Server(self.target, port=389, get_info=ldap3.ALL, 
                                connect_timeout=10)
            
            if password:
                conn = ldap3.Connection(server, 
                                      user=f"{self.domain or ''}\\{username}", 
                                      password=password, 
                                      authentication=ldap3.NTLM)
            else:
                # Hash authentication would require different method
                conn = ldap3.Connection(server, 
                                      user=f"{self.domain or ''}\\{username}", 
                                      password='', 
                                      authentication=ldap3.NTLM)
            
            if conn.bind():
                print(f"    [+] Authenticated as {username}")
                
                # Get user's group memberships
                groups = self.get_user_groups(conn, username)
                
                # Check for admin groups
                admin_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins', 
                              'Administrators', 'Backup Operators', 'Account Operators']
                
                for group in groups:
                    if any(admin_group.lower() in group.lower() for admin_group in admin_groups):
                        paths.append({
                            'username': username,
                            'group': group,
                            'type': 'Group Membership',
                            'escalation': 'Already in admin group',
                            'level': 'HIGH'
                        })
                        print(f"    [+] User is in admin group: {group}")
                
                # Check for interesting permissions
                # (This would require more complex LDAP queries)
                
                conn.unbind()
            else:
                print(f"    [!] Failed to authenticate as {username}")
        
        except Exception as e:
            print(f"    [!] Error finding escalation paths: {e}")
        
        return paths
    
    def get_user_groups(self, conn: ldap3.Connection, username: str) -> List[str]:
        """Get user's group memberships"""
        groups = []
        
        try:
            # Search for user
            search_filter = f'(sAMAccountName={username})'
            conn.search(search_base='', search_filter=search_filter, 
                       attributes=['memberOf'])
            
            if conn.entries:
                for entry in conn.entries:
                    if hasattr(entry, 'memberOf'):
                        for group_dn in entry.memberOf:
                            # Extract group name from DN
                            group_name = str(group_dn).split(',')[0].replace('CN=', '')
                            groups.append(group_name)
        
        except Exception as e:
            print(f"      [!] Error getting groups: {e}")
        
        return groups
