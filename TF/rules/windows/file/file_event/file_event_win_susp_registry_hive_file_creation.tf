resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_susp_registry_hive_file_creation" {
  name                       = "file_event_win_susp_registry_hive_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Hive File Staged Outside Standard User Profile Path"
  description                = <<DESC
    Detects the creation of a registry hive file (UsrClass.dat or NTUSER.DAT) outside of the standard user profile path. These files generally contain various user-specific registry settings and are typically located in the user's profile directory. Staging these files outside of the standard path can be indicative of an attacker attempting to manipulate user registry settings for persistence, privilege escalation, or dump user registry hives for credential harvesting.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_event/file_event_win_susp_registry_hive_file_creation.yml

    False Positives:
    - Backup or profile migration software
    - Forensic acquisition tools
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "\\UsrClass.dat" or FolderPath endswith "\\NTUSER.DAT") and (not((FolderPath matches regex "(?i)^C:\\\\Users\\\\[^\\\\]+\\\\NTUSER\\.DAT$" or (FolderPath startswith "C:\\Windows\\System32\\config\\" or FolderPath startswith "C:\\Windows\\SYSVOL\\" or FolderPath startswith "C:\\Windows\\ServiceProfiles\\") or FolderPath endswith "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "CredentialAccess"]
  techniques                 = ["T1548", "T1003"]
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