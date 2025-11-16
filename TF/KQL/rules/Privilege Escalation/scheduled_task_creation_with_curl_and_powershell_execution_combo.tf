resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_task_creation_with_curl_and_powershell_execution_combo" {
  name                       = "scheduled_task_creation_with_curl_and_powershell_execution_combo"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Scheduled Task Creation with Curl and PowerShell Execution Combo"
  description                = "Detects the creation of a scheduled task using schtasks.exe, potentially in combination with curl for downloading payloads and PowerShell for executing them. This facilitates executing malicious payloads or connecting with C&C server persistently without dropping the malware sample on the host. - Legitimate use of schtasks for administrative purposes. - Automation scripts combining curl and PowerShell in controlled environments."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "curl " and ProcessCommandLine contains "http" and ProcessCommandLine contains "-o") and ((ProcessCommandLine contains " -create " or ProcessCommandLine contains " /create " or ProcessCommandLine contains " –create " or ProcessCommandLine contains " —create " or ProcessCommandLine contains " ―create ") and FolderPath endswith "\\schtasks.exe") and ProcessCommandLine contains "powershell"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence", "DefenseEvasion", "CommandAndControl"]
  techniques                 = ["T1053", "T1218", "T1105"]
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
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}