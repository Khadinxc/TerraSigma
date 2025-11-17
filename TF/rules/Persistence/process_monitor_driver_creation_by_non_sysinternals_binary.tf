resource "azurerm_sentinel_alert_rule_scheduled" "process_monitor_driver_creation_by_non_sysinternals_binary" {
  name                       = "process_monitor_driver_creation_by_non_sysinternals_binary"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Monitor Driver Creation By Non-Sysinternals Binary"
  description                = "Detects creation of the Process Monitor driver by processes other than Process Monitor (procmon) itself. - Some false positives may occur with legitimate renamed process monitor binaries"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\procmon" and FolderPath endswith ".sys") and (not((InitiatingProcessFolderPath endswith "\\procmon.exe" or InitiatingProcessFolderPath endswith "\\procmon64.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1068"]
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