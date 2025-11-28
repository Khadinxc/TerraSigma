resource "azurerm_sentinel_alert_rule_scheduled" "rundll32_execution_with_uncommon_dll_extension" {
  name                       = "rundll32_execution_with_uncommon_dll_extension"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Rundll32 Execution With Uncommon DLL Extension"
  description                = "Detects the execution of rundll32 with a command line that doesn't contain a common extension"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE") and (not((ProcessCommandLine =~ "" or ((ProcessCommandLine contains ".cpl " or ProcessCommandLine contains ".cpl," or ProcessCommandLine contains ".cpl\"" or ProcessCommandLine contains ".cpl'" or ProcessCommandLine contains ".dll " or ProcessCommandLine contains ".dll," or ProcessCommandLine contains ".dll\"" or ProcessCommandLine contains ".dll'" or ProcessCommandLine contains ".inf " or ProcessCommandLine contains ".inf," or ProcessCommandLine contains ".inf\"" or ProcessCommandLine contains ".inf'") or (ProcessCommandLine endswith ".cpl" or ProcessCommandLine endswith ".dll" or ProcessCommandLine endswith ".inf")) or ProcessCommandLine contains " -localserver " or isnull(ProcessCommandLine) or ((ProcessCommandLine contains ":\\Windows\\Installer\\" and ProcessCommandLine contains ".tmp" and ProcessCommandLine contains "zzzzInvokeManagedCustomActionOutOfProc") and InitiatingProcessFolderPath endswith "\\msiexec.exe")))) and (not((InitiatingProcessCommandLine contains ":\\Users\\" and InitiatingProcessCommandLine contains "\\AppData\\Local\\Microsoft\\EdgeUpdate\\Install\\{" and InitiatingProcessCommandLine contains "\\EDGEMITMP_" and InitiatingProcessCommandLine contains ".tmp\\setup.exe" and InitiatingProcessCommandLine contains "--install-archive=" and InitiatingProcessCommandLine contains "--previous-version=" and InitiatingProcessCommandLine contains "--msedgewebview --verbose-logging --do-not-launch-msedge --user-level")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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