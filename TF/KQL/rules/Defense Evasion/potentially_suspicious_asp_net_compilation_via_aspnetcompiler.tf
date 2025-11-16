resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_asp_net_compilation_via_aspnetcompiler" {
  name                       = "potentially_suspicious_asp_net_compilation_via_aspnetcompiler"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious ASP.NET Compilation Via AspNetCompiler"
  description                = "Detects execution of \"aspnet_compiler.exe\" with potentially suspicious paths for compilation."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\Users\\Public\\" or ProcessCommandLine contains "\\AppData\\Local\\Temp\\" or ProcessCommandLine contains "\\AppData\\Local\\Roaming\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains ":\\Windows\\System32\\Tasks\\" or ProcessCommandLine contains ":\\Windows\\Tasks\\") and (FolderPath contains ":\\Windows\\Microsoft.NET\\Framework\\" or FolderPath contains ":\\Windows\\Microsoft.NET\\Framework64\\" or FolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm\\" or FolderPath contains ":\\Windows\\Microsoft.NET\\FrameworkArm64\\") and FolderPath endswith "\\aspnet_compiler.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1127"]
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