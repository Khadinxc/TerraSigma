resource "azurerm_sentinel_alert_rule_scheduled" "darkgate_autoit3_exe_file_creation_by_uncommon_process" {
  name                       = "darkgate_autoit3_exe_file_creation_by_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DarkGate - Autoit3.EXE File Creation By Uncommon Process"
  description                = "Detects the usage of curl.exe, KeyScramblerLogon, or other non-standard/suspicious processes used to create Autoit3.exe. This activity has been associated with DarkGate malware, which uses Autoit3.exe to execute shellcode that performs process injection and connects to the DarkGate command-and-control server. Curl, KeyScramblerLogon, and these other processes consitute non-standard and suspicious ways to retrieve the Autoit3 executable."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\Autoit3.exe" or InitiatingProcessFolderPath endswith "\\curl.exe" or InitiatingProcessFolderPath endswith "\\ExtExport.exe" or InitiatingProcessFolderPath endswith "\\KeyScramblerLogon.exe" or InitiatingProcessFolderPath endswith "\\wmprph.exe") and FolderPath endswith "\\Autoit3.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl", "Execution"]
  techniques                 = ["T1105", "T1059"]
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