resource "azurerm_sentinel_alert_rule_scheduled" "system_information_discovery_using_ioreg" {
  name                       = "system_information_discovery_using_ioreg"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Information Discovery Using Ioreg"
  description                = "Detects the use of \"ioreg\" which will show I/O Kit registry information. This process is used for system information discovery. It has been observed in-the-wild by calling this process directly or using bash and grep to look for specific strings. - Legitimate administrative activities"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-l" or ProcessCommandLine contains "-c") and (ProcessCommandLine contains "AppleAHCIDiskDriver" or ProcessCommandLine contains "IOPlatformExpertDevice" or ProcessCommandLine contains "Oracle" or ProcessCommandLine contains "Parallels" or ProcessCommandLine contains "USB Vendor Name" or ProcessCommandLine contains "VirtualBox" or ProcessCommandLine contains "VMware") and (FolderPath endswith "/ioreg" or ProcessCommandLine contains "ioreg")
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