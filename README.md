# 🔥 ReaperAD v3.0 - Active Directory Exploitation Framework

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)

**ReaperAD** is a comprehensive, production-ready Active Directory exploitation framework designed for authorized security testing. It automates the complete attack chain from reconnaissance to domain compromise with built-in safety controls.

## 🚨 **CRITICAL DISCLAIMER**

> ⚠️ **FOR AUTHORIZED TESTING ONLY**
> 
> This tool is intended for:
> - Legitimate penetration testing with **written permission**
> - Security research in controlled lab environments
> - Educational purposes
> - Defensive security training
> 
> **Unauthorized use is illegal and unethical.** You must comply with:
> - Computer Fraud and Abuse Act (CFAA)
> - Applicable data protection laws
> - Organization security policies

## 🛡️ **Built-in Safety Features**

ReaperAD prioritizes safety with multiple protective mechanisms:

✅ **No Account Lockouts**: Intelligent password spraying avoids lockout policies  
✅ **Rate Limiting**: Configurable delays between requests  
✅ **Attempt Caps**: Maximum 500 total authentication attempts  
✅ **Stealth Mode**: Random jitter (1-3 seconds) between operations  
✅ **Read-Only Operations**: No modifications to target systems  
✅ **Session Management**: Minimizes authentication attempts  

## 📊 **Features**

### 1. **Discovery & Enumeration**
- LDAP anonymous bind detection
- DNS-based domain controller discovery
- SMB signing configuration analysis
- User/group enumeration

### 2. **Credential Acquisition**
- **AS-REP Roasting**: Zero-credential attack against misconfigured accounts
- **Intelligent Password Spraying**: Safe, rate-limited credential testing
- **Kerberoasting**: Service account hash extraction (requires credentials)

### 3. **Privilege Escalation & Domain Compromise**
- **DCSync Attack**: Domain replication for hash dumping
- **Session Management**: Credential caching and reuse
- **Comprehensive Reporting**: JSON and console output

## 🚀 **Installation**

### Prerequisites
- Python 3.8 or higher
- Kali Linux or similar security distribution

## 🛠️ Installation

```bash
# 1. Clone repository
git clone https://github.com/samsatwork7/Reaper-AD.git
cd Reaper-AD

# 2. Create virtual environment (RECOMMENDED)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run tool
python reaperad.py --help
