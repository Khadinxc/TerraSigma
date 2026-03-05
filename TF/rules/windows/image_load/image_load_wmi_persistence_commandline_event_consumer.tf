resource "azurerm_sentinel_alert_rule_scheduled" "image_load_wmi_persistence_commandline_event_consumer" {
  name                       = "image_load_wmi_persistence_commandline_event_consumer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WMI Persistence - Command Line Event Consumer"
  description                = <<DESC
    Detects WMI command line event consumers

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_wmi_persistence_commandline_event_consumer.yml

    False Positives:
    - Unknown (data set is too small; further testing needed)
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe" and FolderPath endswith "\\wbemcons.dll"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1546"]
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