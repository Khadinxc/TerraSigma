resource "azurerm_sentinel_alert_rule_scheduled" "tap_installer_execution" {
  name                       = "tap_installer_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Tap Installer Execution"
  description                = "Well-known TAP software installation. Possible preparation for data exfiltration using tunneling techniques - Legitimate OpenVPN TAP installation"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\tapinstall.exe" and (not(((FolderPath contains ":\\Program Files\\Avast Software\\SecureLine VPN\\" or FolderPath contains ":\\Program Files (x86)\\Avast Software\\SecureLine VPN\\") or FolderPath contains ":\\Program Files\\OpenVPN Connect\\drivers\\tap\\" or FolderPath contains ":\\Program Files (x86)\\Proton Technologies\\ProtonVPNTap\\installer\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Exfiltration"]
  techniques                 = ["T1048"]
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