resource "azurerm_sentinel_alert_rule_scheduled" "scr_file_write_event" {
  name                       = "scr_file_write_event"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "SCR File Write Event"
  description                = "Detects the creation of screensaver files (.scr) outside of system folders. Attackers may execute an application as an \".SCR\" file using \"rundll32.exe desk.cpl,InstallScreenSaver\" for example. - The installation of new screen savers by third party software"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".scr" and (not((FolderPath contains ":\\$WINDOWS.~BT\\NewOS\\" or FolderPath contains ":\\Windows\\System32\\" or FolderPath contains ":\\Windows\\SysWOW64\\" or FolderPath contains ":\\Windows\\WinSxS\\" or FolderPath contains ":\\WUDownloadCache\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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