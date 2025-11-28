resource "azurerm_sentinel_alert_rule_scheduled" "scheduled_taskcache_change_by_uncommon_program" {
  name                       = "scheduled_taskcache_change_by_uncommon_program"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Scheduled TaskCache Change by Uncommon Program"
  description                = "Monitor the creation of a new key under 'TaskCache' when a new scheduled task is registered by a process that is not svchost.exe, which is suspicious"
  severity                   = "High"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache*" and (not((RegistryValueData =~ "(Empty)" or (InitiatingProcessFolderPath =~ "C:\\Windows\\explorer.exe" and RegistryKey endswith "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Microsoft\\Windows\\PLA\\Server Manager Performance Monitor*") or InitiatingProcessFolderPath endswith "C:\\Windows\\System32\\MoUsoCoreWorker.exe" or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\msiexec.exe" or (InitiatingProcessFolderPath endswith "\\ngen.exe" and InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\Framework" and (RegistryKey contains "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{B66B135D-DA06-4FC4-95F8-7458E1D10129}" or RegistryKey contains "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\Microsoft\\Windows\\.NET Framework\\.NET Framework NGEN")) or isnull(RegistryValueData) or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Microsoft Office\\root\\Integration\\Integrator.exe", "C:\\Program Files (x86)\\Microsoft Office\\root\\Integration\\Integrator.exe", "C:\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\OfficeC2RClient.exe", "C:\\Program Files (x86)\\Common Files\\microsoft shared\\ClickToRun\\OfficeC2RClient.exe")) or (RegistryKey contains "Microsoft\\Windows\\UpdateOrchestrator" or RegistryKey contains "Microsoft\\Windows\\SoftwareProtectionPlatform\\SvcRestartTask\\Index" or RegistryKey contains "Microsoft\\Windows\\Flighting\\OneSettings\\RefreshCache\\Index") or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\RuntimeBroker.exe" or InitiatingProcessFolderPath endswith "C:\\Windows\\System32\\services.exe" or InitiatingProcessFolderPath =~ "C:\\WINDOWS\\system32\\svchost.exe" or InitiatingProcessFolderPath =~ "System" or (InitiatingProcessFolderPath endswith "\\TiWorker.exe" and InitiatingProcessFolderPath startswith "C:\\Windows\\")))) and (not(((InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Dropbox\\Update\\DropboxUpdate.exe", "C:\\Program Files\\Dropbox\\Update\\DropboxUpdate.exe")) or (InitiatingProcessFolderPath endswith "C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" or InitiatingProcessFolderPath endswith "C:\\Program Files\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe") or (InitiatingProcessFolderPath endswith "C:\\Program Files (x86)\\Microsoft OneDrive\\OneDrive.exe" or InitiatingProcessFolderPath endswith "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053"]
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