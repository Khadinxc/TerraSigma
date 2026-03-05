resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_userinit_uncommon_child_processes" {
  name                       = "proc_creation_win_userinit_uncommon_child_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Userinit Child Process"
  description                = <<DESC
    Detects uncommon "userinit.exe" child processes, which could be a sign of uncommon shells or login scripts used for persistence.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_userinit_uncommon_child_processes.yml

    False Positives:
    - Legitimate logon scripts or custom shells may trigger false positives. Apply additional filters accordingly.
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\userinit.exe" and (not(FolderPath endswith ":\\WINDOWS\\explorer.exe")) and (not(((FolderPath endswith ":\\Program Files (x86)\\Citrix\\HDX\\bin\\cmstart.exe" or FolderPath endswith ":\\Program Files (x86)\\Citrix\\HDX\\bin\\icast.exe" or FolderPath endswith ":\\Program Files (x86)\\Citrix\\System32\\icast.exe" or FolderPath endswith ":\\Program Files\\Citrix\\HDX\\bin\\cmstart.exe" or FolderPath endswith ":\\Program Files\\Citrix\\HDX\\bin\\icast.exe" or FolderPath endswith ":\\Program Files\\Citrix\\System32\\icast.exe") or isnull(FolderPath) or (ProcessCommandLine contains "netlogon.bat" or ProcessCommandLine contains "UsrLogon.cmd") or (FolderPath endswith ":\\Windows\\System32\\proquota.exe" or FolderPath endswith ":\\Windows\\SysWOW64\\proquota.exe") or ProcessCommandLine =~ "PowerShell.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1037"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}