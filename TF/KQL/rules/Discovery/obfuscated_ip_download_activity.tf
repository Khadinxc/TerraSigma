resource "azurerm_sentinel_alert_rule_scheduled" "obfuscated_ip_download_activity" {
  name                       = "obfuscated_ip_download_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Obfuscated IP Download Activity"
  description                = "Detects use of an encoded/obfuscated version of an IP address (hex, octal...) in an URL combined with a download command"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains "iwr " or ProcessCommandLine contains "Invoke-RestMethod" or ProcessCommandLine contains "irm " or ProcessCommandLine contains "wget " or ProcessCommandLine contains "curl " or ProcessCommandLine contains "DownloadFile" or ProcessCommandLine contains "DownloadString") and ((ProcessCommandLine contains " 0x" or ProcessCommandLine contains "//0x" or ProcessCommandLine contains ".0x" or ProcessCommandLine contains ".00x") or (ProcessCommandLine contains "http://%" and ProcessCommandLine contains "%2e") or (ProcessCommandLine matches regex "https?://[0-9]{1,3}\\.[0-9]{1,3}\\.0[0-9]{3,4}" or ProcessCommandLine matches regex "https?://[0-9]{1,3}\\.0[0-9]{3,7}" or ProcessCommandLine matches regex "https?://0[0-9]{3,11}" or ProcessCommandLine matches regex "https?://(0[0-9]{1,11}\\.){3}0[0-9]{1,11}" or ProcessCommandLine matches regex "https?://0[0-9]{1,11}" or ProcessCommandLine matches regex " [0-7]{7,13}")) and (not(ProcessCommandLine matches regex "https?://((25[0-5]|(2[0-4]|1\\d|[1-9])?\\d)(\\.|\\b)){4}"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
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