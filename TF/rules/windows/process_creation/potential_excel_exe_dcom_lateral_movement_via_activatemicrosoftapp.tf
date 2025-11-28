resource "azurerm_sentinel_alert_rule_scheduled" "potential_excel_exe_dcom_lateral_movement_via_activatemicrosoftapp" {
  name                       = "potential_excel_exe_dcom_lateral_movement_via_activatemicrosoftapp"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Excel.EXE DCOM Lateral Movement Via ActivateMicrosoftApp"
  description                = "Detects suspicious child processes of Excel which could be an indicator of lateral movement leveraging the \"ActivateMicrosoftApp\" Excel DCOM object."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessVersionInfoOriginalFileName in~ ("foxprow.exe", "schdplus.exe", "winproj.exe")) or (FolderPath endswith "\\foxprow.exe" or FolderPath endswith "\\schdplus.exe" or FolderPath endswith "\\winproj.exe")) and InitiatingProcessFolderPath endswith "\\excel.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement"]
  techniques                 = ["T1021"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}