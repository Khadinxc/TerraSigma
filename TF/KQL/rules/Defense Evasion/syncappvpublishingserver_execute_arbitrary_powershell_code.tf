resource "azurerm_sentinel_alert_rule_scheduled" "syncappvpublishingserver_execute_arbitrary_powershell_code" {
  name                       = "syncappvpublishingserver_execute_arbitrary_powershell_code"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "SyncAppvPublishingServer Execute Arbitrary PowerShell Code"
  description                = "Executes arbitrary PowerShell code using SyncAppvPublishingServer.exe. - App-V clients"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\"n; " and (FolderPath endswith "\\SyncAppvPublishingServer.exe" or ProcessVersionInfoOriginalFileName =~ "syncappvpublishingserver.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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