resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_powershell_search_order_hijacking_task" {
  name                       = "potential_persistence_via_powershell_search_order_hijacking_task"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Powershell Search Order Hijacking - Task"
  description                = "Detects suspicious powershell execution via a schedule task where the command ends with an suspicious flags to hide the powershell instance instead of executeing scripts or commands. This could be a sign of persistence via PowerShell \"Get-Variable\" technique as seen being used in Colibri Loader"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine endswith " -windowstyle hidden" or ProcessCommandLine endswith " -w hidden" or ProcessCommandLine endswith " -ep bypass" or ProcessCommandLine endswith " -noni") and (InitiatingProcessCommandLine contains "-k netsvcs" and InitiatingProcessCommandLine contains "-s Schedule") and InitiatingProcessFolderPath =~ "C:\\WINDOWS\\System32\\svchost.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053", "T1059"]
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