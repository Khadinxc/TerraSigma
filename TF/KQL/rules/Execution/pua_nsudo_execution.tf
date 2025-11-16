resource "azurerm_sentinel_alert_rule_scheduled" "pua_nsudo_execution" {
  name                       = "pua_nsudo_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - NSudo Execution"
  description                = "Detects the use of NSudo tool for command execution - Legitimate use by administrators"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-U:S " or ProcessCommandLine contains "-U:T " or ProcessCommandLine contains "-U:E " or ProcessCommandLine contains "-P:E " or ProcessCommandLine contains "-M:S " or ProcessCommandLine contains "-M:H " or ProcessCommandLine contains "-U=S " or ProcessCommandLine contains "-U=T " or ProcessCommandLine contains "-U=E " or ProcessCommandLine contains "-P=E " or ProcessCommandLine contains "-M=S " or ProcessCommandLine contains "-M=H " or ProcessCommandLine contains "-ShowWindowMode:Hide") and ((FolderPath endswith "\\NSudo.exe" or FolderPath endswith "\\NSudoLC.exe" or FolderPath endswith "\\NSudoLG.exe") or (ProcessVersionInfoOriginalFileName in~ ("NSudo.exe", "NSudoLC.exe", "NSudoLG.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1569"]
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