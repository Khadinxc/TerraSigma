resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_cmd_shell_output_redirect" {
  name                       = "potentially_suspicious_cmd_shell_output_redirect"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious CMD Shell Output Redirect"
  description                = "Detects inline Windows shell commands redirecting output via the \">\" symbol to a suspicious location. This technique is sometimes used by malicious actors in order to redirect the output of reconnaissance commands such as \"hostname\" and \"dir\" to files for future exfiltration. - Legitimate admin or third party scripts used for diagnostic collection might generate some false positives"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\cmd.exe" or ProcessVersionInfoOriginalFileName =~ "Cmd.Exe") and (((ProcessCommandLine contains ">" and ProcessCommandLine contains "%APPDATA%\\") or (ProcessCommandLine contains ">" and ProcessCommandLine contains "%TEMP%\\") or (ProcessCommandLine contains ">" and ProcessCommandLine contains "%TMP%\\") or (ProcessCommandLine contains ">" and ProcessCommandLine contains "%USERPROFILE%\\") or (ProcessCommandLine contains ">" and ProcessCommandLine contains "C:\\ProgramData\\") or (ProcessCommandLine contains ">" and ProcessCommandLine contains "C:\\Temp\\") or (ProcessCommandLine contains ">" and ProcessCommandLine contains "C:\\Users\\Public\\") or (ProcessCommandLine contains ">" and ProcessCommandLine contains "C:\\Windows\\Temp\\")) or ((ProcessCommandLine contains " >" or ProcessCommandLine contains "\">" or ProcessCommandLine contains "'>") and (ProcessCommandLine contains "C:\\Users\\" and ProcessCommandLine contains "\\AppData\\Local\\")))
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