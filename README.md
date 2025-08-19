# ReconBud 🕵️‍♂️

ReconBud is a **GUI-based reconnaissance toolkit** for bug bounty hunters and pentesters.  
It wraps popular recon tools into a hacker-style interface using **Python + Tkinter**.

---

## ✨ Features

- **Subdomain Enumeration**
  - Passive: Sublist3r, Assetfinder, Subfinder, Findomain, GitHub, Chaos
  - Active: PureDNS, DNSx
  - Scope filtering (in-scope / out-of-scope)
  - Option to run tools **in parallel** or **one by one** (for low-end PCs)

- **Live/Dead Checker**
  - Splits domains into `live.txt` and `dead.txt`
  - Status-code filtering: `200.txt`, `300.txt`, `400.txt`, `500.txt`

- **Directory / File Bruteforce**
  - Supports: ffuf, gobuster, dirsearch, wfuzz, nikto
  - Build candidate URLs from wordlist
  - Combined results with `httpx`

- **Hacker UI**
  - Green-on-black terminal style
  - Scrollable interface (works on small screens)
  - Multi-line input for multiple targets (runs one by one)

---

## 📦 Requirements

### Python
- Python 3.7+
- Tkinter (GUI library, usually pre-installed)

Install Tkinter if missing:
```
sudo apt update
sudo apt install -y python3-tk
````

### Python modules

```
pip3 install requests dnspython
```

### Recon Tools

ReconBud depends on these tools (must be in `$PATH`):

* [Sublist3r](https://github.com/aboul3la/Sublist3r)
* [assetfinder](https://github.com/tomnomnom/assetfinder)
* [subfinder](https://github.com/projectdiscovery/subfinder)
* [findomain](https://github.com/findomain/findomain)
* [puredns](https://github.com/d3mondev/puredns)
* [dnsx](https://github.com/projectdiscovery/dnsx)
* [httpx](https://github.com/projectdiscovery/httpx)
* [ffuf](https://github.com/ffuf/ffuf)
* [gobuster](https://github.com/OJ/gobuster)
* [dirsearch](https://github.com/maurosoria/dirsearch)
* [wfuzz](https://github.com/xmendez/wfuzz)
* [nikto](https://github.com/sullo/nikto)
* (optional) [chaos](https://github.com/projectdiscovery/chaos-client)
* (optional) [github-subdomains.py](https://github.com/gwen001/github-subdomains)

---

## ⚡ Quick Install (Kali/Ubuntu)

Run this script to install everything:

```
#!/bin/bash
sudo apt update

# Basic deps
sudo apt install -y python3 python3-pip python3-tk git curl wget build-essential

# Python modules
pip3 install requests dnspython

# Install Go if not installed
if ! command -v go &> /dev/null; then
  echo "[*] Installing Go..."
  wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
  sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> ~/.bashrc
  source ~/.bashrc
fi

# Recon tools (Go-based)
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/puredns/v2@latest
go install github.com/ffuf/ffuf@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Other tools via git
mkdir -p ~/tools
cd ~/tools
git clone https://github.com/aboul3la/Sublist3r.git
git clone https://github.com/maurosoria/dirsearch.git
git clone https://github.com/xmendez/wfuzz.git
git clone https://github.com/sullo/nikto.git
git clone https://github.com/gwen001/github-subdomains.git

# Findomain binary
wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux -O /usr/local/bin/findomain
chmod +x /usr/local/bin/findomain

echo "✅ All tools installed! Make sure ~/go/bin is in your PATH."
```

Save it as `install.sh`, then run:

```
chmod +x install.sh
./install.sh
```

Add Go bin path to your shell (if not already):

``
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

---

## 🚀 Usage

1. Run ReconBud:

   ```
   python3 reconbud.py
   ```

2. Use the tabs:

   * **Subdomain Enumeration** → enter domain, wordlist, tokens, run tools.
   * **Live/Dead Checker** → upload subdomains file, split into live/dead/status.
   * **Dir/File Bruteforce** → enter target URL + wordlist, select tools, run.

---

## 📂 Output

Results are stored in auto-created folders:

* `recon_<domain>/subdomains/` → subdomain enumeration files
* `recon_<domain>/dirbusting/` → directory brute-force results

Inside you’ll find:

* `clean_subdomains.txt` → final deduped list
* `live.txt`, `dead.txt`, `200.txt` … → HTTP status splits
* `ffuf.txt`, `gobuster.txt`, etc. → per-tool output

---

## ⚠️ Disclaimer

This tool is for **educational and authorized penetration testing only**.
The author is not responsible for misuse or illegal activity.

---

## 🐉 Author
Tallal Adnan
Built with ❤️ by a bug bounty hunter for bug bounty hunters.
