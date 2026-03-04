resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_public_folder" {
  name                       = "proc_creation_win_powershell_public_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Execution of Powershell Script in Public Folder"
  description                = "This rule detects execution of PowerShell scripts located in the \"C:\\Users\\Public\" folder Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_public_folder.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_public_folder.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-f C:\\Users\\Public" or ProcessCommandLine contains "-f \"C:\\Users\\Public" or ProcessCommandLine contains "-f %Public%" or ProcessCommandLine contains "-fi C:\\Users\\Public" or ProcessCommandLine contains "-fi \"C:\\Users\\Public" or ProcessCommandLine contains "-fi %Public%" or ProcessCommandLine contains "-fil C:\\Users\\Public" or ProcessCommandLine contains "-fil \"C:\\Users\\Public" or ProcessCommandLine contains "-fil %Public%" or ProcessCommandLine contains "-file C:\\Users\\Public" or ProcessCommandLine contains "-file \"C:\\Users\\Public" or ProcessCommandLine contains "-file %Public%") and (FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}