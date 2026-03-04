resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_dd_file_overwrite" {
  name                       = "proc_creation_lnx_dd_file_overwrite"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DD File Overwrite"
  description                = "Detects potential overwriting and deletion of a file using DD. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_dd_file_overwrite.yml - Any user deleting files that way. | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_dd_file_overwrite.yml"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath in~ ("/bin/dd", "/usr/bin/dd")) and ProcessCommandLine contains "of=" and (ProcessCommandLine contains "if=/dev/zero" or ProcessCommandLine contains "if=/dev/null")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1485"]
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