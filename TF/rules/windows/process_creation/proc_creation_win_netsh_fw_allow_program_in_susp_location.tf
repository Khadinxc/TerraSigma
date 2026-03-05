resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_netsh_fw_allow_program_in_susp_location" {
  name                       = "proc_creation_win_netsh_fw_allow_program_in_susp_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Program Location Whitelisted In Firewall Via Netsh.EXE"
  description                = <<DESC
    Detects Netsh command execution that whitelists a program located in a suspicious location in the Windows Firewall

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_netsh_fw_allow_program_in_susp_location.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "firewall" and ProcessCommandLine contains "add" and ProcessCommandLine contains "allowedprogram") or (ProcessCommandLine contains "advfirewall" and ProcessCommandLine contains "firewall" and ProcessCommandLine contains "add" and ProcessCommandLine contains "rule" and ProcessCommandLine contains "action=allow" and ProcessCommandLine contains "program=")) and (FolderPath endswith "\\netsh.exe" or ProcessVersionInfoOriginalFileName =~ "netsh.exe") and (ProcessCommandLine contains ":\\$Recycle.bin\\" or ProcessCommandLine contains ":\\RECYCLER.BIN\\" or ProcessCommandLine contains ":\\RECYCLERS.BIN\\" or ProcessCommandLine contains ":\\SystemVolumeInformation\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains ":\\Users\\Default\\" or ProcessCommandLine contains ":\\Users\\Desktop\\" or ProcessCommandLine contains ":\\Users\\Public\\" or ProcessCommandLine contains ":\\Windows\\addins\\" or ProcessCommandLine contains ":\\Windows\\cursors\\" or ProcessCommandLine contains ":\\Windows\\debug\\" or ProcessCommandLine contains ":\\Windows\\drivers\\" or ProcessCommandLine contains ":\\Windows\\fonts\\" or ProcessCommandLine contains ":\\Windows\\help\\" or ProcessCommandLine contains ":\\Windows\\system32\\tasks\\" or ProcessCommandLine contains ":\\Windows\\Tasks\\" or ProcessCommandLine contains ":\\Windows\\Temp\\" or ProcessCommandLine contains "\\Downloads\\" or ProcessCommandLine contains "\\Local Settings\\Temporary Internet Files\\" or ProcessCommandLine contains "\\Temporary Internet Files\\Content.Outlook\\" or ProcessCommandLine contains "%Public%\\" or ProcessCommandLine contains "%TEMP%" or ProcessCommandLine contains "%TMP%")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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