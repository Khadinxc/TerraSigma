resource "azurerm_sentinel_alert_rule_scheduled" "windows_event_log_access_tampering_via_registry" {
  name                       = "windows_event_log_access_tampering_via_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Event Log Access Tampering Via Registry"
  description                = "Detects changes to the Windows EventLog channel permission values. It focuses on changes to the Security Descriptor Definition Language (SDDL) string, as modifications to these values can restrict access to specific users or groups, potentially aiding in defense evasion by controlling who can view or modify a event log channel. Upon execution, the user shouldn't be able to access the event log channel via the event viewer or via utilities such as \"Get-EventLog\" or \"wevtutil\". - Administrative activity, still unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where ((RegistryKey endswith "\\SYSTEM\\CurrentControlSet\\Services\\EventLog*" and RegistryKey endswith "\\CustomSD") or ((RegistryKey endswith "\\Policies\\Microsoft\\Windows\\EventLog*" or RegistryKey contains "\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels") and RegistryKey endswith "\\ChannelAccess")) and (RegistryValueData contains "D:(D;" or (RegistryValueData contains "D:(" and RegistryValueData contains ")(D;")) and (not(((InitiatingProcessFolderPath endswith "\\TiWorker.exe" and InitiatingProcessFolderPath startswith "C:\\Windows\\WinSxS\\") or InitiatingProcessFolderPath =~ "C:\\Windows\\servicing\\TrustedInstaller.exe"))) and (not((InitiatingProcessFolderPath =~ "" or isnull(InitiatingProcessFolderPath))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence", "DefenseEvasion"]
  techniques                 = ["T1547", "T1112"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }

  entity_mapping {
    entity_type = "RegistryValue"
    field_mapping {
      identifier  = "Value"
      column_name = "RegistryValueData"
    }
  }
}