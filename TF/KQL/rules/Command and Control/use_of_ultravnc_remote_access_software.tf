resource "azurerm_sentinel_alert_rule_scheduled" "use_of_ultravnc_remote_access_software" {
  name                       = "use_of_ultravnc_remote_access_software"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Use of UltraVNC Remote Access Software"
  description                = "An adversary may use legitimate desktop support and remote access software,to establish an interactive command and control channel to target systems within networks - Legitimate use"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoFileDescription =~ "VNCViewer" or ProcessVersionInfoProductName =~ "UltraVNC VNCViewer" or ProcessVersionInfoCompanyName =~ "UltraVNC" or ProcessVersionInfoOriginalFileName =~ "VNCViewer.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]
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
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
  }
}