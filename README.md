# 🛡️ AstraSOAR: Autonomous Streaming Threat Response & Analysis

**A Production-Grade, Live-Network Security Operations Center (SOC) built for the Agents League Hackathon.**

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Streamlit](https://img.shields.io/badge/Streamlit-UI-FF4B4B.svg)
![Scapy](https://img.shields.io/badge/Scapy-Network%20Sensing-green.svg)
![GenAI](https://img.shields.io/badge/Gemini-AI%20Analyst-orange.svg)

## 🎯 Project Overview
Most compliance agents parse static text documents. **AstraSOAR** operates at the kernel layer. 

This project is a fully autonomous, live-network Intrusion Detection and Prevention System (IDPS). It binds directly to the physical Network Interface Card (NIC), sniffing raw socket telemetry in real-time to detect, classify, and neutralize cyberattacks before they exhaust system resources. 

By integrating **Shannon Entropy Analysis**, **Multi-Vector Threat Detection**, and a **Generative AI Analyst**, this platform bridges the gap between low-level packet analysis and high-level, human-readable security orchestration.

---

## 🧠 The Multi-Agent Architecture

The system utilizes a decoupled, three-stage agent pipeline:

## System Architecture
![Astra-SOAR Architecture](https://github.com/user-attachments/assets/4ff1a36c-128a-4eeb-8f67-0415858cdeef)

### 1. The Ingress Sensor Agent (Data Plane)
Built on `Scapy`, this agent continuously monitors raw IP/TCP/UDP frames on the active network interface. It uses dual-matrix tracking to identify anomalies without relying on static signature updates:
* **Velocity Matrix:** Detects Volumetric Floods (DoS/DDoS) by tracking packet arrival frequencies. If an IP exceeds 40 pps with payloads >500 bytes, it triggers the threshold.
* **Spatial Matrix:** Detects Stealth Reconnaissance (Port Scanning) by tracking destination port variations. If a single IP sweeps >15 unique local ports within a 1-second window, it flags the recon attempt.
* **UDP Flood Detection:** Monitors high-volume UDP traffic patterns targeting service disruption.

### 2. The Intelligence Agent (Reasoning Plane)
Once an anomaly is detected, the **Shannon Entropy** of the raw packet payload is mathematically calculated (0–8 bits, normalised to 0–10 scale). The agent then enriches the raw network data:
* **Generative AI SOC Analyst:** Streams the telemetry to a Large Language Model (Gemini 2.5 Flash) to dynamically generate a natural-language executive incident brief for human operators.
* **Rule-based Fallback:** If no API key is configured, the system generates structured severity-classified briefs autonomously.

### 3. The Remediator Agent (Action Plane)
Acting as the autonomous shield, this agent instantly compiles and logs dynamic Linux firewall commands (`iptables -A INPUT -s [IP] -j REJECT --reject-with tcp-reset`) to mathematically sever the attacker's connection and restore infrastructure integrity. Furthermore, it automatically compiles and exports highly structured **PDF Forensic Incident Reports** for every detected threat, ensuring immediate compliance logging.

---

## 🚀 How to Run Locally

### 1. Prerequisites
- **Python 3.11+**
- **Npcap** (Windows) or **libpcap** (Linux/macOS) — required by Scapy for raw packet capture.
- **Administrator / root privileges** — required for NIC-level sniffing.

### 2. Installation
### Step 1: Clone the repository
```bash
git clone https://github.com/Techmasternikhil/Astra-SOAR
cd Astra-SOAR
```
### Step 2: Create a virtual environment
### Windows
```
python -m venv .venv
.venv\Scripts\activate        # Windows
```
### Linux/macOS:
```
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
```
### Step 3: Install dependencies
```
pip install -r requirements.txt
```

### 3. Running the Simulation
To verify AstraSOAR's autonomous response mechanisms, you can simulate real-world traffic patterns from a secondary device (like a smartphone via Termux):

**Simulate Stealth Recon (Nmap):**
```bash
nmap -sS -p 8000-8050 [YOUR_LOCAL_IP]
```
