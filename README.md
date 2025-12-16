# LinPrivesque

LinPrivesque is a modular Linux privilege-escalation enumeration framework written in Python.
It performs systematic analysis across core attack surfaces — PATH, cron, SUID/SGID, sudo, capabilities, system configuration, kernel versioning, networking exposure, and world-writable locations — while generating structured risk assessments for each category.

It is designed for learning, auditing, and defensive validation, with readable JSON-like output suitable for future reporting formats.

## ⚠️ Important Disclaimers

1. Intended Use — Legal / Ethical Notice

LinPrivesque is designed only for defensive security, education, and authorised auditing.

You must not run this tool on systems you do not own or administer.
Unauthorised enumeration can violate the UK Computer Misuse Act and institutional policies.

The developer assumes no liability for misuse.

2. Non-Destructive Enumeration Only

LinPrivesque does not exploit vulnerabilities or modify protected system files.
It reads publicly available data using safe system commands (find, ls, ip, ss, getcap, etc.).

The tool may be noisy on very large filesystems but is otherwise safe.

3. Sudo Behaviour — Please Read

The sudo module begins with:

sudo -k

This intentionally invalidates your cached sudo timestamp, ensuring the enumeration does not accidentally inherit previous sudo privileges.
This does not elevate privileges and does not modify system configuration.

If you rely on an active sudo session, be aware it will be cleared.

4. Dependencies

LinPrivesque requires:

Python 3.8+
rich (pip install rich)


No other external packages are required.

## ✨ Features

LinPrivesque is divided into modular checks.
Each module returns:

{
    
  "info": { ... },

  "risks": [ ... ]

}

Modules Included
### ✔ system_info

Collects:

kernel, arch, OS version

hostname, user, groups

PATH value

uptime

### ✔ path

Finds:

writable directories in PATH

dangerous PATH ordering

nonexistent PATH entries (hijackable locations)

### ✔ capabilities

Enumerates Linux file capabilities:

extracts capabilities recursively

flags dangerous capabilities (cap_sys_admin, cap_setuid, etc.)

identifies writable binaries and writable capability directories

detects non-root-owned capability files

### ✔ sudo

Reports:

whether sudo can be used

whether password is required

lists rules safely

identifies escalation-relevant rules

### ✔ suid

Checks:

all SUID/SGID binaries

writable privileged binaries

non-root-owned privileged binaries

potential GTFOBins escalation vectors

### ✔ cron

Enumerates:

system cron files & permissions

writable cron entries

non-root-owned system cron files

insecure PATH usage in crontab

relative-path cron commands (PATH hijacking risk)

### ✔ kernel_info

Identifies:

kernel version

vulnerable kernel ranges (DirtyCow, DirtyPipe, OverlayFS, etc.)

ASLR settings

ptrace_scope settings

### ✔ networking

Extracts:

network interfaces & IP addresses

listening services

active connections

DNS configuration

routing table

ARP table

risks such as exposed services, internal DNS leakage, unusual outbound connections

### ✔ writable

Finds:

world-writable directories (excluding system pseudo-filesystems)

world-writable system files

world-writable root-owned files

writable files under /etc/systemd or /etc/init.d (persistence risks)

## 📦 Installation

Clone the repository:

git clone https://github.com/kareemmahfouf/LinPrivesque.git

cd LinPrivesque


Install dependency:

pip install rich

## ▶️ Usage

Run from the project root:

python3 main.py


You will see an interactive prompt and formatted output for each module.

## 🧠 Design Philosophy

Simple, modular architecture

Readable output — human-friendly and script-friendly

No exploitation, purely enumeration

Designed as a personal project to apply my knowledge and learn more about PE in linux 

## 📜 License

MIT License — free to modify, improve, and distribute.