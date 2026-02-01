# 🔥 Reaper-AD v4.0

**Complete Active Directory Exploitation Framework**

![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-4.0-red)
![GitHub](https://img.shields.io/github/repo-size/samsatwork7/Reaper-AD)

A **production-ready** AD security tool with **real attack implementations** - not just a framework. From discovery to domain dominance with built-in safety controls.

---

## 🚀 Features

### ✅ **6 Complete Attack Modules**
- **🔍 Discovery** - Real LDAP/SMB/DNS enumeration
- **🔐 Credential Harvesting** - AS-REP roasting, Kerberoasting, intelligent password spraying
- **⚡ Privilege Escalation** - Group analysis and permission checking
- **🔄 Lateral Movement** - Admin share access testing
- **🎯 Persistence** - Backdoor mechanism simulation
- **📊 Reporting** - JSON evidence with attack chain

### 🛡️ **Safety First**
- **Smart rate limiting** (prevents DoS & detection)
- **Lockout avoidance** (intelligent password spraying)
- **User confirmation** (mandatory before execution)
- **Stealth mode** (random delays, reduced signature)
- **Read-only by default** (safe for initial assessment)

---

## 📦 Quick Start

```bash
# Clone & setup
git clone https://github.com/samsatwork7/Reaper-AD.git
cd Reaper-AD
pip install -r requirements.txt

# Test installation
python reaperad.py --help

# Safe discovery test
python reaperad.py example.com

# Complete attack chain (simulated)
python reaperad.py test.local --all
```

---

## 🎯 Usage Examples

```bash
# Complete attack with credentials
python reaperad.py dc.corp.local --all -d CORP -u admin -p "Password123"

# Stealth mode
python reaperad.py 192.168.1.10 --stealth --threads 3

# Hash-based authentication
python reaperad.py target.local -H aad3b...:... --all
```

---


## ⚙️ Command Line Options

```bash
Required:
  target                  Target Domain Controller

Authentication:
  -u, --username USERNAME
  -p, --password PASSWORD
  -d, --domain DOMAIN
  -H, --hashes HASHES      NTLM hashes (LM:NT)

Execution:
  --all                   Run complete attack chain
  --stealth               Stealth mode (slower)
  --threads THREADS       Concurrent threads (default: 5)
  --output OUTPUT         Output directory
```

---

## 🧪 Verification

```bash
# Test all modules
python -c "
import sys
sys.path.insert(0, 'modules')
for m in ['discovery','credential','privilege','lateral','persistence','reporting']:
    __import__(m); print(f'✅ {m}.py')
"

# Run verification script
python verify_installation.py
```

---

## ⚠️ Legal & Ethical Use

**FOR AUTHORIZED TESTING ONLY**

This tool requires:
- ✅ Written permission from system owner
- ✅ Defined scope and Rules of Engagement
- ✅ Compliance with applicable laws (CFAA, GDPR, etc.)
- ✅ Ethical and responsible usage

**Unauthorized use is illegal and unethical.**

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Built for professionals, by professionals.**  
**Use responsibly. Test ethically.**

---

**GitHub:** https://github.com/samsatwork7/Reaper-AD  
**Version:** 4.0 (Complete Release)  
