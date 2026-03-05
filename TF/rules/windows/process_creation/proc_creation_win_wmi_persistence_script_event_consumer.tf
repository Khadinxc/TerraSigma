resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_wmi_persistence_script_event_consumer" {
  name                       = "proc_creation_win_wmi_persistence_script_event_consumer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "WMI Persistence - Script Event Consumer"
  description                = <<DESC
    Detects WMI script event consumers

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wmi_persistence_script_event_consumer.yml

    False Positives:
    - Legitimate event consumers
    - Dell computers on some versions register an event consumer that is known to cause false positives when brightness is changed by the corresponding keyboard button
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath =~ "C:\\WINDOWS\\system32\\wbem\\scrcons.exe" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\svchost.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
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