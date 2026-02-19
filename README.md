# Wazuh 4.14 Automated Installer

This repository contains a production-ready Bash script that automates the deployment of the **Wazuh 4.14** platform on a single Linux host.

It is intended for quickstart installations, proof-of-concept setups, lab environments, and small to medium security monitoring deployments.

---

## Overview

The installer provisions and configures the three core Wazuh components on the same machine:

- **Wazuh Server** – Handles agent enrollment, log processing, rule evaluation, and alert generation.
- **Wazuh Indexer** – Stores and indexes security events using an OpenSearch-based backend for fast querying.
- **Wazuh Dashboard** – Provides a web-based interface for data visualization, alert investigation, and system administration.

After execution, you will have a fully operational Wazuh environment suitable for monitoring up to **100 endpoints** in a single-node configuration.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                           Single Node                           │
│ ┌──────────────────┐ ┌──────────────────┐ ┌────────────────┐    │
│ │    Server        │ │      Indexer     │ │    Dashboard   │    │
│ │ (wazuh-manager)  │ │   (opensearch)   │ │   (dashboard)  │    │
│ └──────────────────┘ └──────────────────┘ └────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

### Component Interaction

- The **Server** receives logs and security telemetry from agents.
- Processed alerts are forwarded to the **Indexer**, where they are stored and made searchable.
- The **Dashboard** queries the Indexer and communicates with the Server API to provide centralized management.

---

## Hardware Requirements

System resource requirements scale according to:

- Number of monitored agents  
- Event volume  
- Alert retention duration  

The table below outlines recommended specifications for a **single-node deployment** retaining approximately **90 days of indexed alert data**.

| Agents  | CPU     | RAM    | Storage (90 days) |
|---------|---------|--------|-------------------|
| 1–25    | 4 vCPU  | 8 GiB  | 50 GB             |
| 25–50   | 8 vCPU  | 8 GiB  | 100 GB            |
| 50–100  | 8 vCPU  | 8 GiB  | 200 GB            |

For environments exceeding 100 agents, a distributed architecture is recommended. Wazuh supports clustering for both the Server and Indexer, enabling horizontal scaling and high availability.

> Hardware guidance is derived from official Wazuh deployment recommendations and adapted for single-node quickstart usage.

---

## Operating System Requirements

The Wazuh central components require a 64-bit Linux environment running on one of the following CPU architectures:

- `x86_64` / `AMD64`
- `AARCH64` / `ARM64`

### Supported Linux Distributions

- Amazon Linux 2 / 2023  
- CentOS Stream 10  
- Red Hat Enterprise Linux 7, 8, 9, 10  
- Ubuntu 16.04, 18.04, 20.04, 22.04, 24.04  
- Kali Linux (additional configuration required)

This installer is designed for Debian-based systems using `apt`, and has been validated on:

- Ubuntu 20.04 / 22.04  
- Debian 11 / 12  
- Kali Linux (with tuning adjustments)

---

## Kali Linux System Tuning

When deploying on Kali Linux, additional kernel and resource limits must be adjusted due to the Indexer’s requirements.

Run the following commands **before** executing the installer:

```bash
# Increase virtual memory map count
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >> /etc/sysctl.conf

# Increase file descriptor limits
ulimit -n 65536
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Disable swap
swapoff -a
# To make permanent, comment out swap entries in /etc/fstab
```

### Why These Settings Matter

- `vm.max_map_count`: Required for OpenSearch memory mapping.
- `nofile` limits: The Indexer opens many files simultaneously.
- Disabling swap: Prevents JVM instability and improves performance.

---

## Installation Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/your-org/wazuh-4.14-automated-installer.git
cd wazuh-4.14-automated-installer
```

### 2. Make the Script Executable

```bash
chmod +x install.sh
```

### 3. Execute as Root

```bash
sudo ./install.sh
```

---

## What the Script Performs

- Verifies required system utilities and internet access  
- Detects the host’s primary IP address  
- Downloads official Wazuh installation scripts and templates  
- Generates configuration files  
- Installs Indexer, Server, and Dashboard  
- Waits for services to initialize  
- Displays dashboard access credentials  

Estimated installation time: **5–10 minutes**

---

## Example Output

```
========== INSTALLATION COMPLETE ==========
Dashboard URL : https://192.168.1.100
Username      : admin
Password      : ********

Browser will show a certificate warning – accept the self-signed certificate.
Full installation log: /var/log/wazuh-install.log
```

---

## Security Notice

- Self-signed certificates are used by default.
- Do not expose the Dashboard directly to the internet.
- Use firewall rules or VPN protection.
- Change default credentials immediately after installation.

---

## Troubleshooting

| Issue | Recommended Action |
|-------|-------------------|
| `curl: (7) Failed to connect` | Verify internet connectivity and firewall |
| `vm.max_map_count` error | Apply system tuning steps |
| Indexer API not responding | Check `systemctl status wazuh-indexer` |
| `tar: not a tar archive` | Remove files and re-run installer |
| Insufficient memory | Ensure at least 8 GB RAM |
| Server not starting | Inspect `/var/ossec/logs/ossec.log` |

---

## License

Released under the MIT License. See the `LICENSE` file for details.

---

## Author

Siddeswar – DevOps / Security Automation
