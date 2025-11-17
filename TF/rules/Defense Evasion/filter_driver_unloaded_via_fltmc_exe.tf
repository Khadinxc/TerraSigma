resource "azurerm_sentinel_alert_rule_scheduled" "filter_driver_unloaded_via_fltmc_exe" {
  name                       = "filter_driver_unloaded_via_fltmc_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Filter Driver Unloaded Via Fltmc.EXE"
  description                = "Detect filter driver unloading activity via fltmc.exe"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "unload" and (FolderPath endswith "\\fltMC.exe" or ProcessVersionInfoOriginalFileName =~ "fltMC.exe")) and (not((((ProcessCommandLine endswith "unload rtp_filesystem_filter" or ProcessCommandLine endswith "unload rtp_filter") and (InitiatingProcessFolderPath contains "\\AppData\\Local\\Temp\\" or InitiatingProcessFolderPath contains ":\\Windows\\Temp\\") and InitiatingProcessFolderPath endswith "\\endpoint-protection-installer-x64.tmp") or (ProcessCommandLine endswith "unload DFMFilter" and InitiatingProcessFolderPath =~ "C:\\Program Files (x86)\\ManageEngine\\uems_agent\\bin\\dcfaservice64.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1070", "T1562"]
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