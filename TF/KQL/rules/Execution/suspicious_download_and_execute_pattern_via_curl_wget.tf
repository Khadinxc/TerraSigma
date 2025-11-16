resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_download_and_execute_pattern_via_curl_wget" {
  name                       = "suspicious_download_and_execute_pattern_via_curl_wget"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Download and Execute Pattern via Curl/Wget"
  description                = "Detects suspicious use of command-line tools such as curl or wget to download remote content - particularly scripts - into temporary directories (e.g., /dev/shm, /tmp), followed by immediate execution, indicating potential malicious activity. This pattern is commonly used by malicious scripts, stagers, or downloaders in fileless or multi-stage Linux attacks. - System update scripts using temporary files - Installer scripts or automated provisioning tools"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "/curl" or ProcessCommandLine contains "/wget") and ProcessCommandLine contains "sh -c" and (ProcessCommandLine contains "/tmp/" or ProcessCommandLine contains "/dev/shm/")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059", "T1203"]
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