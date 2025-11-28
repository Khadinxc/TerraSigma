resource "azurerm_sentinel_alert_rule_scheduled" "always_install_elevated_windows_installer" {
  name                       = "always_install_elevated_windows_installer"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Always Install Elevated Windows Installer"
  description                = "Detects Windows Installer service (msiexec.exe) trying to install MSI packages with SYSTEM privilege - System administrator usage - Anti virus products - WindowsApps located in \"C:\\Program Files\\WindowsApps\\\""
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (((FolderPath contains "\\Windows\\Installer\\" and FolderPath contains "msi") and FolderPath endswith "tmp") or (FolderPath endswith "\\msiexec.exe" and (ProcessIntegrityLevel in~ ("System", "S-1-16-16384")))) and (AccountName contains "AUTHORI" or AccountName contains "AUTORI") and (not(((InitiatingProcessFolderPath startswith "C:\\Program Files\\Avast Software\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Avast Software\\") or InitiatingProcessFolderPath startswith "C:\\ProgramData\\Avira\\" or (InitiatingProcessFolderPath startswith "C:\\Program Files\\Google\\Update\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Google\\Update\\") or InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\services.exe" or (ProcessCommandLine endswith "\\system32\\msiexec.exe /V" or InitiatingProcessCommandLine endswith "\\system32\\msiexec.exe /V") or InitiatingProcessFolderPath startswith "C:\\ProgramData\\Sophos\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}