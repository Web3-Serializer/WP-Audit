# 🛡️ WP‑Audit  
**AI‑Powered & Modular WordPress Security Scanner**

WP‑Audit is a fully modular, AI‑powered auditing tool designed to analyze WordPress installations, detect vulnerabilities, evaluate security posture, and generate detailed reports in HTML or Markdown.  
Featuring TLS‑aware requests, proxy support, automatic CVE/exploit detection, module prioritization, and optional brute‑force testing (authorized), WP‑Audit adapts to any engagement.

> ⚠️ **Legal Notice**  
> WP‑Audit is an offensive security tool intended **only for authorized penetration testing, auditing, and research**.  
> You must have **explicit permission** from the owner of any target you scan or brute‑force.  
> The author and contributors are **not responsible for misuse or damages**.

---

## ✨ Features

- 🤖 **AI‑Powered Audit Reports**  
- 📄 **HTML & Markdown report building**  
- 🧱 **Completely modular (priority‑based)**  
- 🔍 **Automatic CVE & Exploit detection**  
- 🔒 **Full TLS Requests**  
- 🌐 **Proxy support**  
- 🚀 **Aggressive mode scanning**  
- 🔐 **Password bruting (authorized use only)**  
- 🧩 **Easy module creation**  

---

## 📦 Installation

```bash
git clone https://github.com/Web3-Serializer/WP-Audit
cd WP-Audit
pip install -r requirements.txt
```

---

## ⚙️ Model Configuration (AI)

WP‑Audit uses an AI model to enhance Markdown reports.

### **1. Copy the example environment file**
```bash
cp .env.example
```

### **2. Install Ollama**
Download from: https://ollama.com/download

### **3. Pull the model**  
Default model:
```bash
ollama pull qwen2.5:7b
```

### **4. Change model in `.env`**
```
MODEL_NAME=qwen2.5:7b
```

---

## 🕹️ Usage

```
main.py [-h] [--user-agent USER_AGENT] [--browser BROWSER] [--modules MODULES] [--list-modules]
        [--threads THREADS] [--aggressive] [--brute {admin,enum}] [--check-vulns]
        [--report {html,markdown}] [--proxy PROXY]
        target_url
```

## Example Usage

Run a full scan on `https://example.com` with multiple modules, 10 threads, aggressive scanning, vulnerability checking, and HTML report generation:

```bash
python3 main.py --threads 10 --aggressive --check-vulns --report html https://example.com
```

---

## 🔧 Built‑In Modules

WP‑Audit includes modules for:

- Admin endpoint detection  
- Backup file detection  
- Brute force (authorized only)  
- Fuzzer  
- Exposed .git / .svn detection  
- Directory listing  
- Plugin enumeration  
- Theme enumeration  
- User enumeration  
- Version detection  
- Vulnerability detection (CVE, exploits)  

### 🔍 Automatic CVE & Exploit Detection

The **WP Vulnerabilities** module fetches known security issues:

- WordPress core  
- Installed plugins  
- Installed themes  

Includes:
- CVE ID  
- Description  
- Severity  
- Fixed versions  
- Exploit‑DB references  
- Known exploit indicators  

---

## 🧩 Creating Your Own Module

WP‑Audit’s modular design makes adding features simple.

### **1. Create a file in `/modules/`**
```
modules/
    wp_example.py
```

### **2. Example Module Template**

```python
from modules import ModuleBase
from main import WP_Audit
from libs.logger import Logger

class Module(ModuleBase):
    def __init__(self, wp_audit_instance: WP_Audit):
        super().__init__(wp_audit_instance)

        self.name = "Example Module"
        self.description = "This is an exemple module."
        self.version = "1.0"
        self.author = "Your Name Here"
        self.enabled = True

        self.logger = Logger(moduleName=self.name)

    def run(self):
        if not self.enabled:
            return

        self.logger.info(f"Running {self.name} on {self.target_url}")

        # Simulated data extracted by the module
        example_data = {
            "module_name": self.name,
            "target": self.target_url,
            "message": "This is an example of gathered data.",
            "status": "OK"
        }

        # Add it cleanly into the global audit data dictionary
        self.wp_audit.gathered_informations.setdefault("example_data", [])
        self.wp_audit.gathered_informations["example_data"].append(example_data)

        self.logger.success("Example data added to gathered_informations!")
```

---

## ⭐ Support

If you enjoy WP‑Audit, please star the repository 😊  
