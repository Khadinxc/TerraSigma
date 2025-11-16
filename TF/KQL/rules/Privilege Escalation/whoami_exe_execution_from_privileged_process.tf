resource "azurerm_sentinel_alert_rule_scheduled" "whoami_exe_execution_from_privileged_process" {
  name                       = "whoami_exe_execution_from_privileged_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Whoami.EXE Execution From Privileged Process"
  description                = "Detects the execution of \"whoami.exe\" by privileged accounts that are often abused by threat actors"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessVersionInfoOriginalFileName =~ "whoami.exe" or FolderPath endswith "\\whoami.exe") and (AccountName contains "AUTHORI" or AccountName contains "AUTORI" or AccountName contains "TrustedInstaller")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Discovery"]
  techniques                 = ["T1033"]
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