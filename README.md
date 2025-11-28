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

## What changed in this version

- Introduced `--output-structure` for both converters (`source` or `tactics`).
- Entity mapping logic updated to use valid Microsoft Sentinel entity identifiers per the official docs.
- `Account` and `Host` mappings are now added where reasonable; IPs are added when present in the source schema.
- Terraform generation no longer emits invalid identifiers such as `ProcessName`/`ProcessPath` — those were replaced with `CommandLine`, `Name`, and `Directory` where appropriate.

## Example (updated mapping)

```terraform
resource "azurerm_sentinel_alert_rule_scheduled" "rule_7zip_compressing_dump_files" {
  name = "rule_7zip_compressing_dump_files"
  log_analytics_workspace_id = var.workspace_id
  display_name = "7Zip Compressing Dump Files"
  description = "Detects 7-Zip compressing .dmp/.dump files"
  severity = "Medium"
  query = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains ".dmp" and ProcessVersionInfoFileDescription contains "7-Zip"
QUERY
  query_frequency = "PT1H"
  query_period    = "PT1H"
  tactics = ["Collection"]
  techniques = ["T1560"]
  enabled = true

  entity_mapping {
    entity_type = "Account"
    field_mapping { identifier = "Name" ; column_name = "InitiatingProcessAccountName" }
    field_mapping { identifier = "NTDomain" ; column_name = "InitiatingProcessAccountDomain" }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping { identifier = "HostName" ; column_name = "DeviceName" }
    field_mapping { identifier = "AzureID"  ; column_name = "DeviceId" }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping { identifier = "CommandLine" ; column_name = "ProcessCommandLine" }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping { identifier = "Name" ; column_name = "FileName" }
    field_mapping { identifier = "Directory" ; column_name = "FolderPath" }
  }
}
```

## Next steps

- To regenerate Terraform or YAML outputs with the updated behavior, run the commands above. The scripts print a summary when finished.
- If you want, I can regenerate the Terraform or YAML outputs now and show sample files, or commit this README update to your repo.

If you'd like anything else added to the README (changelog, contributing, license, CI examples), tell me which items and I will update it.
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

## What changed in this version

- Introduced `--output-structure` for both converters (`source` or `tactics`).
- Entity mapping logic updated to use valid Microsoft Sentinel entity identifiers per the official docs.
- `Account` and `Host` mappings are now added where reasonable; IPs are added when present in the source schema.
- Terraform generation no longer emits invalid identifiers such as `ProcessName`/`ProcessPath` — those were replaced with `CommandLine`, `Name`, and `Directory` where appropriate.

## Example (updated mapping)

```terraform
resource "azurerm_sentinel_alert_rule_scheduled" "rule_7zip_compressing_dump_files" {
  name = "rule_7zip_compressing_dump_files"
  log_analytics_workspace_id = var.workspace_id
  display_name = "7Zip Compressing Dump Files"
  description = "Detects 7-Zip compressing .dmp/.dump files"
  severity = "Medium"
  query = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains ".dmp" and ProcessVersionInfoFileDescription contains "7-Zip"
QUERY
  query_frequency = "PT1H"
  query_period    = "PT1H"
  tactics = ["Collection"]
  techniques = ["T1560"]
  enabled = true

  entity_mapping {
    entity_type = "Account"
    field_mapping { identifier = "Name" ; column_name = "InitiatingProcessAccountName" }
    field_mapping { identifier = "NTDomain" ; column_name = "InitiatingProcessAccountDomain" }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping { identifier = "HostName" ; column_name = "DeviceName" }
    field_mapping { identifier = "AzureID"  ; column_name = "DeviceId" }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping { identifier = "CommandLine" ; column_name = "ProcessCommandLine" }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping { identifier = "Name" ; column_name = "FileName" }
    field_mapping { identifier = "Directory" ; column_name = "FolderPath" }
  }
}
```

## Next steps

- To regenerate Terraform or YAML outputs with the updated behavior, run the commands above. The scripts print a summary when finished.
- If you want, I can regenerate the Terraform or YAML outputs now and show sample files, or commit this README update to your repo.

If you'd like anything else added to the README (changelog, contributing, license, CI examples), tell me which items and I will update it.
![Update TerraSigma Detections](https://github.com/Khadinxc/TerraSigma/actions/workflows/update-terrasigma-detections.yml/badge.svg)
![GitHub last commit](https://img.shields.io/github/last-commit/Khadinxc/TerraSigma)
# TerraSigma - Modern Detection Engineering for the Cloud-Native SIEM Microsoft Sentinel - Automated Updates
__Terraform converted Sigma rules for deployment to Microsoft Sentinel. Providing the coverage of all Kusto backend supported pySigma rules and the DevOps practices provided from Terraform including state management, drift detection, and incremental deployment.__

### Usage:
**Clone the Sigma2KQL rules repository:**

``` powershell
git clone https://github.com/Khadinxc/Sigma2KQL.git
```

**Move into the cloned repo:**
``` powershell
cd .\Sigma2KQL
```

**Clone this repository:**
```
git clone https://github.com/Khadinxc/TerraSigma.git
```

**Create your Python virtual environment:**
```
python -m venv .venv
```

**Activate your Python virtual environment with Windows:**
``` powershell
.\.venv\Scripts\Activate.ps1
```

**Activate your Python virtual environment with Linux**
``` bash
./.venv/bin/activate
```

**Once in your Python virtual env:**

``` powershell
pip install -r requirements.txt
```

**Then you can use the script like this:**
``` powershell
python kql_to_terraform.py --kql-dir ./KQL --output-dir ./TF --schemas ./schemas.json
```

**This creates your initial set of Terraform structured detections.**


### Sample Rule:
``` terraform
resource "azurerm_sentinel_alert_rule_scheduled" "rule_7zip_compressing_dump_files" {
  name                       = "rule_7zip_compressing_dump_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "7Zip Compressing Dump Files"
  description                = "Detects execution of 7z in order to compress a file with a \".dmp\"/\".dump\" extension, which could be a step in a process of dump file exfiltration. - Legitimate use of 7z with a command line in which \".dmp\" or \".dump\" appears accidentally - Legitimate use of 7z to compress WER \".dmp\" files for troubleshooting"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ".dmp" or ProcessCommandLine contains ".dump" or ProcessCommandLine contains ".hdmp") and (ProcessVersionInfoFileDescription contains "7-Zip" or (FolderPath endswith "\\7z.exe" or FolderPath endswith "\\7zr.exe" or FolderPath endswith "\\7za.exe") or (ProcessVersionInfoOriginalFileName in~ ("7z.exe", "7za.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1560"]
  enabled                    = true

  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = false
      lookback_duration       = "PT5H"
      reopen_closed_incidents = false
      entity_matching_method  = "AllEntities"
      by_entities             = []
      by_alert_details        = []
      by_custom_details       = []
    }
  }

  event_grouping {
    aggregation_method = "SingleAlert"
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}
```
