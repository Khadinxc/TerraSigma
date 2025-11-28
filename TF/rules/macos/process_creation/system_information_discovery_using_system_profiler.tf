resource "azurerm_sentinel_alert_rule_scheduled" "system_information_discovery_using_system_profiler" {
  name                       = "system_information_discovery_using_system_profiler"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Information Discovery Using System_Profiler"
  description                = "Detects the execution of \"system_profiler\" with specific \"Data Types\" that have been seen being used by threat actors and malware. It provides system hardware and software configuration information. This process is primarily used for system information discovery. However, \"system_profiler\" can also be used to determine if virtualization software is being run for defense evasion purposes. - Legitimate administrative activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "SPApplicationsDataType" or ProcessCommandLine contains "SPHardwareDataType" or ProcessCommandLine contains "SPNetworkDataType" or ProcessCommandLine contains "SPUSBDataType") and (FolderPath endswith "/system_profiler" or ProcessCommandLine contains "system_profiler")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "DefenseEvasion"]
  techniques                 = ["T1082", "T1497"]
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