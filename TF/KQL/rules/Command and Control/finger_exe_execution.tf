resource "azurerm_sentinel_alert_rule_scheduled" "finger_exe_execution" {
  name                       = "finger_exe_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Finger.EXE Execution"
  description                = "Detects execution of the \"finger.exe\" utility. Finger.EXE or \"TCPIP Finger Command\" is an old utility that is still present on modern Windows installation. It Displays information about users on a specified remote computer (typically a UNIX computer) that is running the finger service or daemon. Due to the old nature of this utility and the rareness of machines having the finger service. Any execution of \"finger.exe\" can be considered \"suspicious\" and worth investigating. - Admin activity (unclear what they do nowadays with finger.exe)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessVersionInfoOriginalFileName =~ "finger.exe" or FolderPath endswith "\\finger.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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