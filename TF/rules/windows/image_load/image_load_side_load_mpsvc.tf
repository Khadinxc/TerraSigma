resource "azurerm_sentinel_alert_rule_scheduled" "image_load_side_load_mpsvc" {
  name                       = "image_load_side_load_mpsvc"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential DLL Sideloading Of MpSvc.DLL"
  description                = <<DESC
    Detects potential DLL sideloading of "MpSvc.dll".

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_side_load_mpsvc.yml

    False Positives:
    - Legitimate applications loading their own versions of the DLL mentioned in this rule.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath endswith "\\MpSvc.dll" and (not((FolderPath startswith "C:\\Program Files\\Windows Defender\\" or FolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\" or FolderPath startswith "C:\\Windows\\WinSxS\\")))
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