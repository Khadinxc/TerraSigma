resource "azurerm_sentinel_alert_rule_scheduled" "potential_spn_enumeration_via_setspn_exe" {
  name                       = "potential_spn_enumeration_via_setspn_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential SPN Enumeration Via Setspn.EXE"
  description                = "Detects service principal name (SPN) enumeration used for Kerberoasting - Administration activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -q " or ProcessCommandLine contains " /q ") and (FolderPath endswith "\\setspn.exe" or ProcessVersionInfoOriginalFileName =~ "setspn.exe" or (ProcessVersionInfoFileDescription contains "Query or reset the computer" and ProcessVersionInfoFileDescription contains "SPN attribute"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1558"]
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