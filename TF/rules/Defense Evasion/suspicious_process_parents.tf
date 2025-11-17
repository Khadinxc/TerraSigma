resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_process_parents" {
  name                       = "suspicious_process_parents"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Process Parents"
  description                = "Detects suspicious parent processes that should not have any children or should only have a single possible child program"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith "\\minesweeper.exe" or InitiatingProcessFolderPath endswith "\\winver.exe" or InitiatingProcessFolderPath endswith "\\bitsadmin.exe") or ((InitiatingProcessFolderPath endswith "\\csrss.exe" or InitiatingProcessFolderPath endswith "\\certutil.exe" or InitiatingProcessFolderPath endswith "\\eventvwr.exe" or InitiatingProcessFolderPath endswith "\\calc.exe" or InitiatingProcessFolderPath endswith "\\notepad.exe") and (not((isnull(FolderPath) or (FolderPath endswith "\\WerFault.exe" or FolderPath endswith "\\wermgr.exe" or FolderPath endswith "\\conhost.exe" or FolderPath endswith "\\mmc.exe" or FolderPath endswith "\\win32calc.exe" or FolderPath endswith "\\notepad.exe")))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1036"]
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