resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_using_ntfs_reparse_point_process" {
  name                       = "uac_bypass_using_ntfs_reparse_point_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass Using NTFS Reparse Point - Process"
  description                = "Detects the pattern of UAC Bypass using NTFS reparse point and wusa.exe DLL hijacking (UACMe 36)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith "\\AppData\\Local\\Temp\\update.msu" and ProcessCommandLine startswith "\"C:\\Windows\\system32\\wusa.exe\"  /quiet C:\\Users\\" and (ProcessIntegrityLevel in~ ("High", "System", "S-1-16-16384", "S-1-16-12288"))) or ((ProcessCommandLine contains "C:\\Users\\" and ProcessCommandLine contains "\\AppData\\Local\\Temp\\" and ProcessCommandLine contains "\\dismhost.exe {") and FolderPath endswith "\\DismHost.exe" and (ProcessIntegrityLevel in~ ("High", "System")) and InitiatingProcessCommandLine =~ "\"C:\\Windows\\system32\\dism.exe\" /online /quiet /norestart /add-package /packagepath:\"C:\\Windows\\system32\\pe386\" /ignorecheck")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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