resource "azurerm_sentinel_alert_rule_scheduled" "disabling_windows_defender_wmi_autologger_session_via_reg_exe" {
  name                       = "disabling_windows_defender_wmi_autologger_session_via_reg_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Disabling Windows Defender WMI Autologger Session via Reg.exe"
  description                = "Detects the use of reg.exe to disable the Event Tracing for Windows (ETW) Autologger session for Windows Defender API and Audit events. By setting the 'Start' value to '0' for the 'DefenderApiLogger' or 'DefenderAuditLogger' session, an attacker can prevent these critical security events from being logged, effectively blinding monitoring tools that rely on this data. This is a powerful defense evasion technique. - Highly unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\reg.exe" or ProcessVersionInfoOriginalFileName =~ "reg.exe") and (ProcessCommandLine contains "add" and ProcessCommandLine contains "0") and (ProcessCommandLine contains "\\Control\\WMI\\Autologger\\DefenderApiLogger\\Start" or ProcessCommandLine contains "\\Control\\WMI\\Autologger\\DefenderAuditLogger\\Start")) and (not(ProcessCommandLine contains "0x00000001"))
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
    field_mapping {
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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