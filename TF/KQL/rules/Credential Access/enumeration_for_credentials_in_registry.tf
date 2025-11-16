resource "azurerm_sentinel_alert_rule_scheduled" "enumeration_for_credentials_in_registry" {
  name                       = "enumeration_for_credentials_in_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Enumeration for Credentials in Registry"
  description                = "Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " query " and ProcessCommandLine contains "/t " and ProcessCommandLine contains "REG_SZ" and ProcessCommandLine contains "/s") and FolderPath endswith "\\reg.exe") and ((ProcessCommandLine contains "/f " and ProcessCommandLine contains "HKLM") or (ProcessCommandLine contains "/f " and ProcessCommandLine contains "HKCU") or ProcessCommandLine contains "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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