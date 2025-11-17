resource "azurerm_sentinel_alert_rule_scheduled" "system_information_discovery_via_wmic_exe" {
  name                       = "system_information_discovery_via_wmic_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "System Information Discovery Via Wmic.EXE"
  description                = "Detects the use of the WMI command-line (WMIC) utility to identify and display various system information, including OS, CPU, GPU, disk drive names, memory capacity, display resolution, baseboard, BIOS, and GPU driver products/versions. - VMWare Tools serviceDiscovery scripts"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "caption" or ProcessCommandLine contains "command" or ProcessCommandLine contains "driverversion" or ProcessCommandLine contains "maxcapacity" or ProcessCommandLine contains "name" or ProcessCommandLine contains "osarchitecture" or ProcessCommandLine contains "product" or ProcessCommandLine contains "size" or ProcessCommandLine contains "smbiosbiosversion" or ProcessCommandLine contains "version" or ProcessCommandLine contains "videomodedescription") and (ProcessCommandLine contains "baseboard" or ProcessCommandLine contains "bios" or ProcessCommandLine contains "cpu" or ProcessCommandLine contains "diskdrive" or ProcessCommandLine contains "logicaldisk" or ProcessCommandLine contains "memphysical" or ProcessCommandLine contains "os" or ProcessCommandLine contains "path" or ProcessCommandLine contains "startup" or ProcessCommandLine contains "win32_videocontroller") and ProcessCommandLine contains "get" and (ProcessVersionInfoFileDescription =~ "WMI Commandline Utility" or ProcessVersionInfoOriginalFileName =~ "wmic.exe" or FolderPath endswith "\\WMIC.exe")) and (not(InitiatingProcessCommandLine contains "\\VMware\\VMware Tools\\serviceDiscovery\\scripts\\"))
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}