resource "azurerm_sentinel_alert_rule_scheduled" "uac_bypass_using_consent_and_comctl32_file" {
  name                       = "uac_bypass_using_consent_and_comctl32_file"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UAC Bypass Using Consent and Comctl32 - File"
  description                = "Detects the pattern of UAC Bypass using consent.exe and comctl32.dll (UACMe 22)"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\comctl32.dll" and FolderPath startswith "C:\\Windows\\System32\\consent.exe.@"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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