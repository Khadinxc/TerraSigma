resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_fltmc_unload_driver" {
  name                       = "proc_creation_win_fltmc_unload_driver"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Filter Driver Unloaded Via Fltmc.EXE"
  description                = <<DESC
    Detect filter driver unloading activity via fltmc.exe

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_fltmc_unload_driver.yml
  DESC
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