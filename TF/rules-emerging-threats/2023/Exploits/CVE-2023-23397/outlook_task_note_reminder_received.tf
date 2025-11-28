resource "azurerm_sentinel_alert_rule_scheduled" "outlook_task_note_reminder_received" {
  name                       = "outlook_task_note_reminder_received"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Outlook Task/Note Reminder Received"
  description                = "Detects changes to the registry values related to outlook that indicates that a reminder was triggered for a Note or Task item. This could be a sign of exploitation of CVE-2023-23397. Further investigation is required to determine the success of an exploitation. - Legitimate reminders received for a task or a note will also trigger this rule."
  severity                   = "Low"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\Tasks*" or RegistryKey endswith "\\Notes*") and (RegistryKey endswith "\\SOFTWARE\\Microsoft\\Office*" and RegistryKey endswith "\\Outlook*")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1137"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}