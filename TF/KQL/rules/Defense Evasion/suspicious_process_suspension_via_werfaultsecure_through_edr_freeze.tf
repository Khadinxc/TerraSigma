resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_process_suspension_via_werfaultsecure_through_edr_freeze" {
  name                       = "suspicious_process_suspension_via_werfaultsecure_through_edr_freeze"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Process Suspension via WERFaultSecure through EDR-Freeze"
  description                = "Detects attempts to freeze a process likely an EDR or an antimalware service process through EDR-Freeze that abuses the WerFaultSecure.exe process to suspend security software. - Legitimate usage of WerFaultSecure for debugging purposes"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " /h " and ProcessCommandLine contains " /pid " and ProcessCommandLine contains " /tid " and ProcessCommandLine contains " /encfile " and ProcessCommandLine contains " /cancel " and ProcessCommandLine contains " /type " and ProcessCommandLine contains " 268310") and (FolderPath endswith "\\WerFaultSecure.exe" or ProcessVersionInfoOriginalFileName =~ "WerFaultSecure.exe")
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