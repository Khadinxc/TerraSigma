resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_krbrelay_execution" {
  name                       = "hacktool_krbrelay_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - KrbRelay Execution"
  description                = "Detects the use of KrbRelay, a Kerberos relaying tool - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " -spn " and ProcessCommandLine contains " -clsid " and ProcessCommandLine contains " -rbcd ") or (ProcessCommandLine contains "shadowcred" and ProcessCommandLine contains "clsid" and ProcessCommandLine contains "spn") or (ProcessCommandLine contains "spn " and ProcessCommandLine contains "session " and ProcessCommandLine contains "clsid ") or (FolderPath endswith "\\KrbRelay.exe" or ProcessVersionInfoOriginalFileName =~ "KrbRelay.exe")
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