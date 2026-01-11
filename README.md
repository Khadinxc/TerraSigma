![Update TerraSigma Detections](https://github.com/Khadinxc/TerraSigma/actions/workflows/update-terrasigma-detections.yml/badge.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/Khadinxc/TerraSigma)
# TerraSigma - Modern Detection Engineering for the Cloud-Native SIEM Microsoft Sentinel - Automated Updates
__Terraform-converted Sigma rules for deployment to Microsoft Sentinel.__

This repository automates conversion of Sigma → KQL → Terraform and back to Sentinel YAML, making it easy to manage detection rules with infrastructure-as-code.

Key points:
- The converters now preserve the original Sigma/TF source folder layout by default (`source`).
- You can alternatively group outputs by primary MITRE tactic (`tactics`) using `--output-structure`.
- Entity mappings were updated to use valid Microsoft Sentinel identifiers (Account, Host, Process, File, IP, Registry, URL, etc.).

## Quick Start

1. Clone the Sigma2KQL rules repository:

```powershell
git clone https://github.com/Khadinxc/Sigma2KQL.git
```

2. Clone this repository (TerraSigma):

```powershell
git clone https://github.com/Khadinxc/TerraSigma.git
cd TerraSigma
```

3. Create and activate a Python virtual environment:

Windows (PowerShell):
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:
```bash
python -m venv .venv
source .venv/bin/activate
```

4. Install requirements:

```powershell
pip install -r requirements.txt
```

## kql_to_terraform (KQL/Sigma → Terraform)

Generate Terraform rules from the KQL rules you obtained from `Sigma2KQL`.

Default (preserve the source folder structure under `./TF`):
```powershell
python kql_to_terraform.py --kql-dir ./KQL --output-dir ./TF --schemas ./schemas.json
```

Group outputs by primary MITRE tactic instead (legacy behavior):
```powershell
python kql_to_terraform.py --kql-dir ./KQL --output-dir ./TF --schemas ./schemas.json --output-structure tactics
```

Notes:
- The script tries to map fields to valid Microsoft Sentinel identifiers. `Account` and `Host` mappings are added where the table schema provides suitable fields. `IP` mappings appear for tables that include IP columns (e.g., `DeviceNetworkEvents`).
- File hashes are mapped to `FileHash` identifiers; `File` entity identifiers are `Name` and `Directory`.

## terraform_to_yaml (Terraform → Sentinel YAML)

Convert Terraform rule resources to Azure Sentinel YAML ready for import.

Default (preserve TF folder layout under `./YAML`):
```powershell
python terraform_to_yaml.py --tf-dir ./TF --output-dir ./YAML
```

Group YAML files by primary MITRE tactic instead:
```powershell
python terraform_to_yaml.py --tf-dir ./TF --output-dir ./YAML --output-structure tactics
```

