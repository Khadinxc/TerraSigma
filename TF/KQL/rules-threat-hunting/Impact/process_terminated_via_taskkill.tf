resource "azurerm_sentinel_alert_rule_scheduled" "process_terminated_via_taskkill" {
  name                       = "process_terminated_via_taskkill"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Terminated Via Taskkill"
  description                = "Detects execution of \"taskkill.exe\" in order to stop a service or a process. Look for suspicious parents executing this command in order to hunt for potential malicious activity. Attackers might leverage this in order to conduct data destruction or data encrypted for impact on the data stores of services like Exchange and SQL Server. - Expected FP with some processes using this techniques to terminate one of their processes during installations and updates"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -im " or ProcessCommandLine contains " /im " or ProcessCommandLine contains " –im " or ProcessCommandLine contains " —im " or ProcessCommandLine contains " ―im " or ProcessCommandLine contains " -pid " or ProcessCommandLine contains " /pid " or ProcessCommandLine contains " –pid " or ProcessCommandLine contains " —pid " or ProcessCommandLine contains " ―pid ") and (ProcessCommandLine contains " -f " or ProcessCommandLine contains " /f " or ProcessCommandLine contains " –f " or ProcessCommandLine contains " —f " or ProcessCommandLine contains " ―f " or ProcessCommandLine endswith " -f" or ProcessCommandLine endswith " /f" or ProcessCommandLine endswith " –f" or ProcessCommandLine endswith " —f" or ProcessCommandLine endswith " ―f") and (FolderPath endswith "\\taskkill.exe" or ProcessVersionInfoOriginalFileName =~ "taskkill.exe")) and (not(((InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\" or InitiatingProcessFolderPath contains ":\\Windows\\Temp") and InitiatingProcessFolderPath endswith ".tmp")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1489"]
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