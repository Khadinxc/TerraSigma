resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_macos_hdiutil_mount" {
  name                       = "proc_creation_macos_hdiutil_mount"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disk Image Mounting Via Hdiutil - MacOS"
  description                = <<DESC
    Detects the execution of the hdiutil utility in order to mount disk images.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/macos/process_creation/proc_creation_macos_hdiutil_mount.yml

    False Positives:
    - Legitimate usage of hdiutil by administrators and users.
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "attach " or ProcessCommandLine contains "mount ") and FolderPath endswith "/hdiutil"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Collection"]
  techniques                 = ["T1566", "T1560"]
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