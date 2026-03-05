resource "azurerm_sentinel_alert_rule_scheduled" "file_event_macos_susp_startup_item_created" {
  name                       = "file_event_macos_susp_startup_item_created"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Startup Item File Created - MacOS"
  description                = <<DESC
    Detects the creation of a startup item plist file, that automatically get executed at boot initialization to establish persistence. Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/macos/file_event/file_event_macos_susp_startup_item_created.yml

    False Positives:
    - Legitimate administration activities
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".plist" and (FolderPath startswith "/Library/StartupItems/" or FolderPath startswith "/System/Library/StartupItems")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1037"]
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