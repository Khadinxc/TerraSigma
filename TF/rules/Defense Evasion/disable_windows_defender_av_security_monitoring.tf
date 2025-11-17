resource "azurerm_sentinel_alert_rule_scheduled" "disable_windows_defender_av_security_monitoring" {
  name                       = "disable_windows_defender_av_security_monitoring"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disable Windows Defender AV Security Monitoring"
  description                = "Detects attackers attempting to disable Windows Defender using Powershell - Minimal, for some older versions of dev tools, such as pycharm, developers were known to sometimes disable Windows Defender to improve performance, but this generally is not considered a good security practice."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll"))) and (ProcessCommandLine contains "-DisableBehaviorMonitoring $true" or ProcessCommandLine contains "-DisableRuntimeMonitoring $true")) or ((FolderPath endswith "\\sc.exe" or ProcessVersionInfoOriginalFileName =~ "sc.exe") and ((ProcessCommandLine contains "delete" and ProcessCommandLine contains "WinDefend") or (ProcessCommandLine contains "config" and ProcessCommandLine contains "WinDefend" and ProcessCommandLine contains "start=disabled") or (ProcessCommandLine contains "stop" and ProcessCommandLine contains "WinDefend")))
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