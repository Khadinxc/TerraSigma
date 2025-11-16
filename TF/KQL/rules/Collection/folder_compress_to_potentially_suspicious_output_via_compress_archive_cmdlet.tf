resource "azurerm_sentinel_alert_rule_scheduled" "folder_compress_to_potentially_suspicious_output_via_compress_archive_cmdlet" {
  name                       = "folder_compress_to_potentially_suspicious_output_via_compress_archive_cmdlet"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Folder Compress To Potentially Suspicious Output Via Compress-Archive Cmdlet"
  description                = "Detects PowerShell scripts that make use of the \"Compress-Archive\" Cmdlet in order to compress folders and files where the output is stored in a potentially suspicious location that is used often by malware for exfiltration. An adversary might compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Compress-Archive -Path" and ProcessCommandLine contains "-DestinationPath $env:TEMP") or (ProcessCommandLine contains "Compress-Archive -Path" and ProcessCommandLine contains "-DestinationPath" and ProcessCommandLine contains "\\AppData\\Local\\Temp\\") or (ProcessCommandLine contains "Compress-Archive -Path" and ProcessCommandLine contains "-DestinationPath" and ProcessCommandLine contains ":\\Windows\\Temp\\")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1074"]
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
  }
}