resource "azurerm_sentinel_alert_rule_scheduled" "livekd_driver_creation_by_uncommon_process" {
  name                       = "livekd_driver_creation_by_uncommon_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LiveKD Driver Creation By Uncommon Process"
  description                = "Detects the creation of the LiveKD driver by a process image other than \"livekd.exe\". - Administrators might rename LiveKD before its usage which could trigger this. Add additional names you use to the filter"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath =~ "C:\\Windows\\System32\\drivers\\LiveKdD.SYS" and (not((InitiatingProcessFolderPath endswith "\\livekd.exe" or InitiatingProcessFolderPath endswith "\\livek64.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
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