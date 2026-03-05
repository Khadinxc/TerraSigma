resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_file_and_directory_discovery" {
  name                       = "proc_creation_lnx_file_and_directory_discovery"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File and Directory Discovery - Linux"
  description                = <<DESC
    Detects usage of system utilities such as "find", "tree", "findmnt", etc, to discover files, directories and network shares.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_file_and_directory_discovery.yml

    False Positives:
    - Legitimate activities
  DESC
  severity                   = "Informational"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine matches regex "(.){200,}" and FolderPath endswith "/file") or FolderPath endswith "/find" or FolderPath endswith "/findmnt" or FolderPath endswith "/mlocate" or (ProcessCommandLine contains "-R" and FolderPath endswith "/ls") or FolderPath endswith "/tree"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1083"]
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