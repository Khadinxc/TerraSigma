resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_print_dump_sensitive_files" {
  name                       = "proc_creation_win_print_dump_sensitive_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Sensitive File Dump Via Print.EXE"
  description                = <<DESC
    Detects the abuse of the Print.exe utility for credential harvesting which involves using Print.Exe to copy sensitive files such as ntds.dit, SAM, SECURITY, or SYSTEM from the Windows directory in order to extract credentials, locally or remotely.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_print_dump_sensitive_files.yml

    False Positives:
    - Unlikely
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "\\config\\SAM" or ProcessCommandLine contains "\\config\\SECURITY" or ProcessCommandLine contains "\\config\\SYSTEM" or ProcessCommandLine contains "\\windows\\ntds\\ntds.dit") and (ProcessCommandLine contains "-D" or ProcessCommandLine contains "/D" or ProcessCommandLine contains "–D" or ProcessCommandLine contains "—D" or ProcessCommandLine contains "―D")) and (FolderPath endswith "\\print.exe" or ProcessVersionInfoOriginalFileName =~ "Print.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003", "T1218"]
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