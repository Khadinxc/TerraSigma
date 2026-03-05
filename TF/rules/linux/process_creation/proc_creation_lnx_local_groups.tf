resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_local_groups" {
  name                       = "proc_creation_lnx_local_groups"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Local Groups Discovery - Linux"
  description                = <<DESC
    Detects enumeration of local system groups. Adversaries may attempt to find local system groups and permission settings

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_local_groups.yml

    False Positives:
    - Legitimate administration activities
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "/groups" or (ProcessCommandLine contains "/etc/group" and (FolderPath endswith "/cat" or FolderPath endswith "/ed" or FolderPath endswith "/head" or FolderPath endswith "/less" or FolderPath endswith "/more" or FolderPath endswith "/nano" or FolderPath endswith "/tail" or FolderPath endswith "/vi" or FolderPath endswith "/vim"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1069"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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