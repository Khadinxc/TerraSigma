resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_file_deletion" {
  name                       = "proc_creation_lnx_file_deletion"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Deletion"
  description                = <<DESC
    Detects file deletion using "rm", "shred" or "unlink" commands which are used often by adversaries to delete files left behind by the actions of their intrusion activity

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_file_deletion.yml

    False Positives:
    - Legitimate administration activities
  DESC
  severity                   = "Informational"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/rm" or FolderPath endswith "/shred" or FolderPath endswith "/unlink"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070"]
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