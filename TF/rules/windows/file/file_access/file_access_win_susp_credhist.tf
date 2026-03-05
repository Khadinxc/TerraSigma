resource "azurerm_sentinel_alert_rule_scheduled" "file_access_win_susp_credhist" {
  name                       = "file_access_win_susp_credhist"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Access To Windows Credential History File By Uncommon Applications"
  description                = <<DESC
    Detects file access requests to the Windows Credential History File by an uncommon application. This can be a sign of credential stealing. Example case would be usage of mimikatz "dpapi::credhist" function

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/file/file_access/file_access_win_susp_credhist.yml
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FileName endswith "\\Microsoft\\Protect\\CREDHIST" and (not((InitiatingProcessFolderPath =~ "C:\\Windows\\explorer.exe" or (InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\system32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1555"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}