resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_susp_exec_from_dev_shm" {
  name                       = "proc_creation_lnx_susp_exec_from_dev_shm"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Execution From Shared Memory Directory"
  description                = <<DESC
    Detects the execution of a binary from the Linux shared memory directory /dev/shm. This directory is a tmpfs mount backed entirely by RAM and is abused by attackers for fileless malware staging because files written there never touch physical disk and may evade disk-based detection.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_exec_from_dev_shm.yml

    False Positives:
    - Unlikely in production environments; some container runtimes or IPC frameworks may use /dev/shm for inter-process communication but should not spawn executables.
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath startswith "/dev/shm/"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1027"]
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