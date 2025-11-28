resource "azurerm_sentinel_alert_rule_scheduled" "rdp_enable_or_disable_via_win32_terminalservicesetting_wmi_class" {
  name                       = "rdp_enable_or_disable_via_win32_terminalservicesetting_wmi_class"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "RDP Enable or Disable via Win32_TerminalServiceSetting WMI Class"
  description                = "Detects enabling or disabling of Remote Desktop Protocol (RDP) using alternate methods such as WMIC or PowerShell. In PowerShell one-liner commands, the \"SetAllowTSConnections\" method of the \"Win32_TerminalServiceSetting\" class may be used to enable or disable RDP. In WMIC, the \"rdtoggle\" alias or \"Win32_TerminalServiceSetting\" class may be used for the same purpose. - Legitimate system administrators enabling RDP for remote support - System configuration scripts during deployment"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "rdtoggle" or ProcessCommandLine contains "Win32_TerminalServiceSetting") and ProcessCommandLine contains "SetAllowTSConnections" and ((FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("wmic.exe", "PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement", "Execution"]
  techniques                 = ["T1021", "T1047"]
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