resource "azurerm_sentinel_alert_rule_scheduled" "potential_mpclient_dll_sideloading_via_defender_binaries" {
  name                       = "potential_mpclient_dll_sideloading_via_defender_binaries"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Mpclient.DLL Sideloading Via Defender Binaries"
  description                = "Detects potential sideloading of \"mpclient.dll\" by Windows Defender processes (\"MpCmdRun\" and \"NisSrv\") from their non-default directory. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\MpCmdRun.exe" or FolderPath endswith "\\NisSrv.exe") and (not((FolderPath startswith "C:\\Program Files (x86)\\Windows Defender\\" or FolderPath startswith "C:\\Program Files\\Microsoft Security Client\\" or FolderPath startswith "C:\\Program Files\\Windows Defender\\" or FolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or FolderPath startswith "C:\\Windows\\WinSxS\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion"]
  techniques                 = ["T1574"]
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