resource "azurerm_sentinel_alert_rule_scheduled" "forest_blizzard_apt_file_creation_activity" {
  name                       = "forest_blizzard_apt_file_creation_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Forest Blizzard APT - File Creation Activity"
  description                = "Detects the creation of specific files inside of ProgramData directory. These files were seen being created by Forest Blizzard as described by MSFT. - Unlikely"
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