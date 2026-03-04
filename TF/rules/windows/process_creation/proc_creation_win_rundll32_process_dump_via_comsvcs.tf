resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_rundll32_process_dump_via_comsvcs" {
  name                       = "proc_creation_win_rundll32_process_dump_via_comsvcs"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Memory Dump Via Comsvcs.DLL"
  description                = "Detects a process memory dump via \"comsvcs.dll\" using rundll32, covering multiple different techniques (ordinal, minidump function, etc.) Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE" or ProcessCommandLine contains "rundll32") and ((ProcessCommandLine contains "#-" or ProcessCommandLine contains "#+" or ProcessCommandLine contains "#24" or ProcessCommandLine contains "24 " or ProcessCommandLine contains "MiniDump" or ProcessCommandLine contains "#65560") and (ProcessCommandLine contains "comsvcs" and ProcessCommandLine contains "full"))) or ((ProcessCommandLine contains " #" or ProcessCommandLine contains ",#" or ProcessCommandLine contains ", #" or ProcessCommandLine contains "\"#") and (ProcessCommandLine contains "24" and ProcessCommandLine contains "comsvcs" and ProcessCommandLine contains "full"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess"]
  techniques                 = ["T1036", "T1003"]
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