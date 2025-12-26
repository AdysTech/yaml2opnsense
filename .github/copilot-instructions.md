# Copilot Instructions for yaml2opnsense

These instructions help GitHub Copilot understand the structure, goals, and conventions of the `yaml2opnsense` project so it can generate correct YAML, Python, and documentation.

---

## 🧩 Project Purpose

`yaml2opnsense` is a declarative automation engine for OPNsense.  
It takes a single YAML file describing:

- VLANs  
- DHCP configuration  
- DNS forwarding  
- FreeRADIUS users  
- Firewall policies  
- Service aliases  

…and generates the corresponding OPNsense configuration via API calls.

Copilot should assist by generating **valid YAML**, **Python code**, and **documentation** that follow the project’s conventions.

---

## 🧱 YAML Structure Rules

refer to structure.yaml for detailed schema.


🧰 Python Code Conventions

Copilot should follow these conventions:

Use requests for OPNsense API calls

Use scapy for validation tests

Use PyYAML for parsing

Use clear, deterministic logic

Avoid unnecessary abstractions

Prefer explicit over implicit

🧼 Style & Formatting
YAML: 2‑space indentation

Python: PEP‑8

Comments: concise and meaningful

No trailing whitespace

No tabs

🚫 Things Copilot Should NOT Do
Do not invent new top‑level YAML keys

Do not change the schema structure

Do not generate VLAN IDs or IP ranges outside RFC1918 unless asked

Do not generate passwords unless explicitly requested

Do not reorder user‑provided YAML unless asked