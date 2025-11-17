resource "azurerm_sentinel_alert_rule_scheduled" "cmd_shell_output_redirect" {
  name                       = "cmd_shell_output_redirect"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "CMD Shell Output Redirect"
  description                = "Detects the use of the redirection character \">\" to redirect information on the command line. This technique is sometimes used by malicious actors in order to redirect the output of reconnaissance commands such as \"hostname\" and \"dir\" to files for future exfiltration. - Internet Download Manager extensions use named pipes and redirection via CLI. Filter it out if you use it in your environment"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ">" and (ProcessVersionInfoOriginalFileName =~ "Cmd.Exe" or FolderPath endswith "\\cmd.exe")) and (not((ProcessCommandLine contains "C:\\Program Files (x86)\\Internet Download Manager\\IDMMsgHost.exe" or ProcessCommandLine contains "chrome-extension://" or ProcessCommandLine contains "\\.\\pipe\\chrome.nativeMessaging")))
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