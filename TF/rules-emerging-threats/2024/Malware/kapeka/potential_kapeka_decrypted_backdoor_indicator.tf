resource "azurerm_sentinel_alert_rule_scheduled" "potential_kapeka_decrypted_backdoor_indicator" {
  name                       = "potential_kapeka_decrypted_backdoor_indicator"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Kapeka Decrypted Backdoor Indicator"
  description                = "Detects the presence of a file that is decrypted backdoor binary dropped by the Kapeka Dropper, which disguises itself as a hidden file under a folder named \"Microsoft\" within \"CSIDL_COMMON_APPDATA\" or \"CSIDL_LOCAL_APPDATA\", depending on the process privileges. The file, typically 5-6 characters long with a random combination of consonants and vowels followed by a \".wll\" extension to pose as a legitimate file to evade detection."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where ((FolderPath contains ":\\ProgramData\\" or FolderPath contains "\\AppData\\Local\\") and FolderPath matches regex "\\\\[a-zA-Z]{5,6}\\.wll") or (FolderPath endswith "\\win32log.exe" or FolderPath endswith "\\crdss.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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