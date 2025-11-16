resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_reg_add_bitlocker" {
  name                       = "suspicious_reg_add_bitlocker"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Reg Add BitLocker"
  description                = "Detects suspicious addition to BitLocker related registry keys via the reg.exe utility - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "EnableBDEWithNoTPM" or ProcessCommandLine contains "UseAdvancedStartup" or ProcessCommandLine contains "UseTPM" or ProcessCommandLine contains "UseTPMKey" or ProcessCommandLine contains "UseTPMKeyPIN" or ProcessCommandLine contains "RecoveryKeyMessageSource" or ProcessCommandLine contains "UseTPMPIN" or ProcessCommandLine contains "RecoveryKeyMessage") and (ProcessCommandLine contains "REG" and ProcessCommandLine contains "ADD" and ProcessCommandLine contains "\\SOFTWARE\\Policies\\Microsoft\\FVE" and ProcessCommandLine contains "/v" and ProcessCommandLine contains "/f")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1486"]
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