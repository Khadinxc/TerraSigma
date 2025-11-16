resource "azurerm_sentinel_alert_rule_scheduled" "insensitive_subfolder_search_via_findstr_exe" {
  name                       = "insensitive_subfolder_search_via_findstr_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Insensitive Subfolder Search Via Findstr.EXE"
  description                = "Detects execution of findstr with the \"s\" and \"i\" flags for a \"subfolder\" and \"insensitive\" search respectively. Attackers sometimes leverage this built-in utility to search the system for interesting files or filter through results of commands. - Administrative or software activity"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "findstr" or FolderPath endswith "findstr.exe" or ProcessVersionInfoOriginalFileName =~ "FINDSTR.EXE") and ((ProcessCommandLine contains " -i " or ProcessCommandLine contains " /i " or ProcessCommandLine contains " –i " or ProcessCommandLine contains " —i " or ProcessCommandLine contains " ―i ") and (ProcessCommandLine contains " -s " or ProcessCommandLine contains " /s " or ProcessCommandLine contains " –s " or ProcessCommandLine contains " —s " or ProcessCommandLine contains " ―s "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess", "CommandAndControl"]
  techniques                 = ["T1218", "T1564", "T1552", "T1105"]
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