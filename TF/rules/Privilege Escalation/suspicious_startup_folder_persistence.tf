resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_startup_folder_persistence" {
  name                       = "suspicious_startup_folder_persistence"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Startup Folder Persistence"
  description                = "Detects the creation of potentially malicious script and executable files in Windows startup folders, which is a common persistence technique used by threat actors. These files (.ps1, .vbs, .js, .bat, etc.) are automatically executed when a user logs in, making the Startup folder an attractive target for attackers. This technique is frequently observed in malvertising campaigns and malware distribution where attackers attempt to maintain long-term access to compromised systems. - Rare legitimate usage of some of the extensions mentioned in the rule"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "\\Windows\\Start Menu\\Programs\\Startup\\" and (FolderPath endswith ".bat" or FolderPath endswith ".cmd" or FolderPath endswith ".dll" or FolderPath endswith ".hta" or FolderPath endswith ".jar" or FolderPath endswith ".js" or FolderPath endswith ".jse" or FolderPath endswith ".msi" or FolderPath endswith ".ps1" or FolderPath endswith ".psd1" or FolderPath endswith ".psm1" or FolderPath endswith ".scr" or FolderPath endswith ".url" or FolderPath endswith ".vba" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs" or FolderPath endswith ".wsf")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1204", "T1547"]
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
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