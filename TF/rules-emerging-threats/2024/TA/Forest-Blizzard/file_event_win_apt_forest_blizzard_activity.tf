resource "azurerm_sentinel_alert_rule_scheduled" "file_event_win_apt_forest_blizzard_activity" {
  name                       = "file_event_win_apt_forest_blizzard_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Forest Blizzard APT - File Creation Activity"
  description                = "Detects the creation of specific files inside of ProgramData directory. These files were seen being created by Forest Blizzard as described by MSFT. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2024/TA/Forest-Blizzard/file_event_win_apt_forest_blizzard_activity.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2024/TA/Forest-Blizzard/file_event_win_apt_forest_blizzard_activity.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where ((FolderPath contains "\\prnms003.inf_" or FolderPath contains "\\prnms009.inf_") and (FolderPath startswith "C:\\ProgramData\\Microsoft\\v" or FolderPath startswith "C:\\ProgramData\\Adobe\\v" or FolderPath startswith "C:\\ProgramData\\Comms\\v" or FolderPath startswith "C:\\ProgramData\\Intel\\v" or FolderPath startswith "C:\\ProgramData\\Kaspersky Lab\\v" or FolderPath startswith "C:\\ProgramData\\Bitdefender\\v" or FolderPath startswith "C:\\ProgramData\\ESET\\v" or FolderPath startswith "C:\\ProgramData\\NVIDIA\\v" or FolderPath startswith "C:\\ProgramData\\UbiSoft\\v" or FolderPath startswith "C:\\ProgramData\\Steam\\v")) or (FolderPath startswith "C:\\ProgramData\\" and ((FolderPath endswith ".save" or FolderPath endswith "\\doit.bat" or FolderPath endswith "\\execute.bat" or FolderPath endswith "\\servtask.bat") or (FolderPath contains "\\wayzgoose" and FolderPath endswith ".dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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