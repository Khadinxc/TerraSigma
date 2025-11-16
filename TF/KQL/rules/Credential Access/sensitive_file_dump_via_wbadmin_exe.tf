resource "azurerm_sentinel_alert_rule_scheduled" "sensitive_file_dump_via_wbadmin_exe" {
  name                       = "sensitive_file_dump_via_wbadmin_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Sensitive File Dump Via Wbadmin.EXE"
  description                = "Detects the dump of highly sensitive files such as \"NTDS.DIT\" and \"SECURITY\" hive. Attackers can leverage the \"wbadmin\" utility in order to dump sensitive files that might contain credential or sensitive information. - Legitimate backup operation by authorized administrators. Matches must be investigated and allowed on a case by case basis."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "start" or ProcessCommandLine contains "backup") and (FolderPath endswith "\\wbadmin.exe" or ProcessVersionInfoOriginalFileName =~ "WBADMIN.EXE") and (ProcessCommandLine contains "\\config\\SAM" or ProcessCommandLine contains "\\config\\SECURITY" or ProcessCommandLine contains "\\config\\SYSTEM" or ProcessCommandLine contains "\\Windows\\NTDS\\NTDS.dit")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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