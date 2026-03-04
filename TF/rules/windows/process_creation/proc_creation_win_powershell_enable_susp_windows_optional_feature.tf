resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_enable_susp_windows_optional_feature" {
  name                       = "proc_creation_win_powershell_enable_susp_windows_optional_feature"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Suspicious Windows Feature Enabled - ProcCreation"
  description                = "Detects usage of the built-in PowerShell cmdlet \"Enable-WindowsOptionalFeature\" used as a Deployment Image Servicing and Management tool. Similar to DISM.exe, this cmdlet is used to enumerate, install, uninstall, configure, and update features and packages in Windows images Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_enable_susp_windows_optional_feature.yml - Legitimate usage of the features listed in the rule. | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_enable_susp_windows_optional_feature.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Enable-WindowsOptionalFeature" and ProcessCommandLine contains "-Online" and ProcessCommandLine contains "-FeatureName") and (ProcessCommandLine contains "TelnetServer" or ProcessCommandLine contains "Internet-Explorer-Optional-amd64" or ProcessCommandLine contains "TFTP" or ProcessCommandLine contains "SMB1Protocol" or ProcessCommandLine contains "Client-ProjFS" or ProcessCommandLine contains "Microsoft-Windows-Subsystem-Linux")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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
}