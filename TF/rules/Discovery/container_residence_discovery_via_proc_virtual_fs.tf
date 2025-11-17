resource "azurerm_sentinel_alert_rule_scheduled" "container_residence_discovery_via_proc_virtual_fs" {
  name                       = "container_residence_discovery_via_proc_virtual_fs"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Container Residence Discovery Via Proc Virtual FS"
  description                = "Detects potential container discovery via listing of certain kernel features in the \"/proc\" virtual filesystem - Legitimate system administrator usage of these commands - Some container tools or deployments may use these techniques natively to determine how they proceed with execution, and will need to be filtered"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "awk" or FolderPath endswith "/cat" or FolderPath endswith "grep" or FolderPath endswith "/head" or FolderPath endswith "/less" or FolderPath endswith "/more" or FolderPath endswith "/nl" or FolderPath endswith "/tail") and (ProcessCommandLine contains "/proc/2/" or (ProcessCommandLine contains "/proc/" and (ProcessCommandLine endswith "/cgroup" or ProcessCommandLine endswith "/sched")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1082"]
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