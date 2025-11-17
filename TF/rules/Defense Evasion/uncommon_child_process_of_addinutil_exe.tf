resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_child_process_of_addinutil_exe" {
  name                       = "uncommon_child_process_of_addinutil_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Child Process Of AddinUtil.EXE"
  description                = "Detects uncommon child processes of the Add-In deployment cache updating utility (AddInutil.exe) which could be a sign of potential abuse of the binary to proxy execution via a custom Addins.Store payload."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\addinutil.exe" and (not((FolderPath endswith ":\\Windows\\System32\\conhost.exe" or FolderPath endswith ":\\Windows\\System32\\werfault.exe" or FolderPath endswith ":\\Windows\\SysWOW64\\werfault.exe")))
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