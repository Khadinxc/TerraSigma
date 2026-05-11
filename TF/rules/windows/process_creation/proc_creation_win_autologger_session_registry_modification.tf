resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_autologger_session_registry_modification" {
  name                       = "proc_creation_win_autologger_session_registry_modification"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows EventLog Autologger Session Registry Modification Via CommandLine"
  description                = <<DESC
    Detects attempts to disable Windows EventLog autologger sessions via registry modification. The AutoLogger event tracing session records events that occur early in the operating system boot process. Applications and device drivers can use the AutoLogger session to capture traces before the user logs in. Adversaries may disable these sessions to evade detection and prevent security monitoring of early boot activities and system events.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_autologger_session_registry_modification.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "add " or ProcessCommandLine contains "Set-ItemProperty" or ProcessCommandLine contains "New-ItemProperty" or ProcessCommandLine contains "si ") and ProcessCommandLine contains "\\Control\\WMI\\Autologger\\" and (ProcessCommandLine contains "Start" or ProcessCommandLine contains "Enabled") and ((FolderPath endswith "\\reg.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("reg.exe", "PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  techniques                 = ["T1685"]
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