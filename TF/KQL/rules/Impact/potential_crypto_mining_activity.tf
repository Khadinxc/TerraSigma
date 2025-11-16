resource "azurerm_sentinel_alert_rule_scheduled" "potential_crypto_mining_activity" {
  name                       = "potential_crypto_mining_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Crypto Mining Activity"
  description                = "Detects command line parameters or strings often used by crypto miners - Legitimate use of crypto miners - Some build frameworks"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " --cpu-priority=" or ProcessCommandLine contains "--donate-level=0" or ProcessCommandLine contains " -o pool." or ProcessCommandLine contains " --nicehash" or ProcessCommandLine contains " --algo=rx/0 " or ProcessCommandLine contains "stratum+tcp://" or ProcessCommandLine contains "stratum+udp://" or ProcessCommandLine contains "LS1kb25hdGUtbGV2ZWw9" or ProcessCommandLine contains "0tZG9uYXRlLWxldmVsP" or ProcessCommandLine contains "tLWRvbmF0ZS1sZXZlbD" or ProcessCommandLine contains "c3RyYXR1bSt0Y3A6Ly" or ProcessCommandLine contains "N0cmF0dW0rdGNwOi8v" or ProcessCommandLine contains "zdHJhdHVtK3RjcDovL" or ProcessCommandLine contains "c3RyYXR1bSt1ZHA6Ly" or ProcessCommandLine contains "N0cmF0dW0rdWRwOi8v" or ProcessCommandLine contains "zdHJhdHVtK3VkcDovL") and (not((ProcessCommandLine contains " pool.c " or ProcessCommandLine contains " pool.o " or ProcessCommandLine contains "gcc -")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1496"]
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