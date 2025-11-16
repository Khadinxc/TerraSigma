resource "azurerm_sentinel_alert_rule_scheduled" "process_access_via_trolleyexpress_exclusion" {
  name                       = "process_access_via_trolleyexpress_exclusion"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Access via TrolleyExpress Exclusion"
  description                = "Detects a possible process memory dump that uses the white-listed Citrix TrolleyExpress.exe filename as a way to dump the lsass process memory"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "\\TrolleyExpress 7" or ProcessCommandLine contains "\\TrolleyExpress 8" or ProcessCommandLine contains "\\TrolleyExpress 9" or ProcessCommandLine contains "\\TrolleyExpress.exe 7" or ProcessCommandLine contains "\\TrolleyExpress.exe 8" or ProcessCommandLine contains "\\TrolleyExpress.exe 9" or ProcessCommandLine contains "\\TrolleyExpress.exe -ma ") or (FolderPath endswith "\\TrolleyExpress.exe" and (not((isnull(ProcessVersionInfoOriginalFileName) or ProcessVersionInfoOriginalFileName contains "CtxInstall"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess"]
  techniques                 = ["T1218", "T1003"]
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