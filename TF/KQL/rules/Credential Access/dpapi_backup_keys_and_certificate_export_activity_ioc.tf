resource "azurerm_sentinel_alert_rule_scheduled" "dpapi_backup_keys_and_certificate_export_activity_ioc" {
  name                       = "dpapi_backup_keys_and_certificate_export_activity_ioc"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DPAPI Backup Keys And Certificate Export Activity IOC"
  description                = "Detects file names with specific patterns seen generated and used by tools such as Mimikatz and DSInternals related to exported or stolen DPAPI backup keys and certificates. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "ntds_capi_" or FolderPath contains "ntds_legacy_" or FolderPath contains "ntds_unknown_") and (FolderPath endswith ".cer" or FolderPath endswith ".key" or FolderPath endswith ".pfx" or FolderPath endswith ".pvk")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1555", "T1552"]
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