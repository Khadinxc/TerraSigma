resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_process_patterns_ntds_dit_exfil" {
  name                       = "suspicious_process_patterns_ntds_dit_exfil"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Process Patterns NTDS.DIT Exfil"
  description                = "Detects suspicious process patterns used in NTDS.DIT exfiltration"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "ac i ntds" and ProcessCommandLine contains "create full") or (ProcessCommandLine contains "/c copy " and ProcessCommandLine contains "\\windows\\ntds\\ntds.dit") or (ProcessCommandLine contains "activate instance ntds" and ProcessCommandLine contains "create full") or (ProcessCommandLine contains "powershell" and ProcessCommandLine contains "ntds.dit") or ((FolderPath endswith "\\NTDSDump.exe" or FolderPath endswith "\\NTDSDumpEx.exe") or (ProcessCommandLine contains "ntds.dit" and ProcessCommandLine contains "system.hiv") or ProcessCommandLine contains "NTDSgrab.ps1")) or (((InitiatingProcessFolderPath contains "\\apache" or InitiatingProcessFolderPath contains "\\tomcat" or InitiatingProcessFolderPath contains "\\AppData\\" or InitiatingProcessFolderPath contains "\\Temp\\" or InitiatingProcessFolderPath contains "\\Public\\" or InitiatingProcessFolderPath contains "\\PerfLogs\\") or (FolderPath contains "\\apache" or FolderPath contains "\\tomcat" or FolderPath contains "\\AppData\\" or FolderPath contains "\\Temp\\" or FolderPath contains "\\Public\\" or FolderPath contains "\\PerfLogs\\")) and ProcessCommandLine contains "ntds.dit")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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