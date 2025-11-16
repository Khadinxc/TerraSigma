resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_edrsilencer_execution" {
  name                       = "hacktool_edrsilencer_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - EDRSilencer Execution"
  description                = "Detects the execution of EDRSilencer, a tool that leverages Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) agents from reporting security events to the server based on PE metadata information. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\EDRSilencer.exe" or ProcessVersionInfoOriginalFileName =~ "EDRSilencer.exe" or ProcessVersionInfoFileDescription contains "EDRSilencer"
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