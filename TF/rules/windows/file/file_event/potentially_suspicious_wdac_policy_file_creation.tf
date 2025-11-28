resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_wdac_policy_file_creation" {
  name                       = "potentially_suspicious_wdac_policy_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious WDAC Policy File Creation"
  description                = "Detects suspicious Windows Defender Application Control (WDAC) policy file creation from abnormal processes that could be abused by attacker to block EDR/AV components while allowing their own malicious code to run on the system. - Administrators and security vendors could leverage WDAC, apply additional filters as needed."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "\\Windows\\System32\\CodeIntegrity\\" and (not((((InitiatingProcessCommandLine contains "ConvertFrom-CIPolicy -XmlFilePath" and InitiatingProcessCommandLine contains "-BinaryFilePath ") or InitiatingProcessCommandLine contains "CiTool --update-policy" or (InitiatingProcessCommandLine contains "Copy-Item -Path" and InitiatingProcessCommandLine contains "-Destination")) or (InitiatingProcessFolderPath endswith "\\Microsoft.ConfigurationManagement.exe" or InitiatingProcessFolderPath endswith "\\WDAC Wizard.exe" or InitiatingProcessFolderPath endswith "C:\\Program Files\\PowerShell\\7-preview\\pwsh.exe" or InitiatingProcessFolderPath endswith "C:\\Program Files\\PowerShell\\7\\pwsh.exe" or InitiatingProcessFolderPath endswith "C:\\Windows\\System32\\dllhost.exe" or InitiatingProcessFolderPath endswith "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe" or InitiatingProcessFolderPath endswith "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" or InitiatingProcessFolderPath endswith "C:\\Windows\\SysWOW64\\dllhost.exe" or InitiatingProcessFolderPath endswith "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell_ise.exe" or InitiatingProcessFolderPath endswith "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe") or InitiatingProcessFolderPath =~ "System")))
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
      column_name = "InitiatingProcessCommandLine"
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