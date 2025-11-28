resource "azurerm_sentinel_alert_rule_scheduled" "elevated_system_shell_spawned" {
  name                       = "elevated_system_shell_spawned"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Elevated System Shell Spawned"
  description                = "Detects when a shell program such as the Windows command prompt or PowerShell is launched with system privileges. Use this rule to hunt for potential suspicious processes."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\cmd.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "powershell_ise.EXE", "pwsh.dll", "Cmd.Exe"))) and (LogonId =~ "0x3e7" and (AccountName contains "AUTHORI" or AccountName contains "AUTORI"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "DefenseEvasion", "Execution"]
  techniques                 = ["T1059"]
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