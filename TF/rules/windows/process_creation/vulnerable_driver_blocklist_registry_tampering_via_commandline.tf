resource "azurerm_sentinel_alert_rule_scheduled" "vulnerable_driver_blocklist_registry_tampering_via_commandline" {
  name                       = "vulnerable_driver_blocklist_registry_tampering_via_commandline"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Vulnerable Driver Blocklist Registry Tampering Via CommandLine"
  description                = "Detects tampering of the Vulnerable Driver Blocklist registry via command line tools such as PowerShell or REG.EXE. The Vulnerable Driver Blocklist is a security feature that helps prevent the loading of known vulnerable drivers. Disabling this feature may indicate an attempt to bypass security controls, often targeted by threat actors to facilitate the installation of malicious or vulnerable drivers, particularly in scenarios involving Endpoint Detection and Response - It is very unlikely for legitimate activities to disable the Vulnerable Driver Blocklist via command line tools; thus it is recommended to investigate promptly."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "add " or ProcessCommandLine contains "New-ItemProperty " or ProcessCommandLine contains "Set-ItemProperty " or ProcessCommandLine contains "si ") and (ProcessCommandLine contains "\\Control\\CI\\Config" and ProcessCommandLine contains "VulnerableDriverBlocklistEnable") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll", "reg.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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