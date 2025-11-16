resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_new_service_creation" {
  name                       = "suspicious_new_service_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious New Service Creation"
  description                = "Detects creation of a new service via \"sc\" command or the powershell \"new-service\" cmdlet with suspicious binary paths - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "New-Service" and ProcessCommandLine contains "-BinaryPathName") or ((ProcessCommandLine contains "create" and ProcessCommandLine contains "binPath=") and FolderPath endswith "\\sc.exe")) and (ProcessCommandLine contains "powershell" or ProcessCommandLine contains "mshta" or ProcessCommandLine contains "wscript" or ProcessCommandLine contains "cscript" or ProcessCommandLine contains "svchost" or ProcessCommandLine contains "dllhost" or ProcessCommandLine contains "cmd " or ProcessCommandLine contains "cmd.exe /c" or ProcessCommandLine contains "cmd.exe /k" or ProcessCommandLine contains "cmd.exe /r" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "C:\\Users\\Public" or ProcessCommandLine contains "\\Downloads\\" or ProcessCommandLine contains "\\Desktop\\" or ProcessCommandLine contains "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" or ProcessCommandLine contains "C:\\Windows\\TEMP\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1543"]
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