resource "azurerm_sentinel_alert_rule_scheduled" "powershell_module_file_created_by_non_powershell_process" {
  name                       = "powershell_module_file_created_by_non_powershell_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Module File Created By Non-PowerShell Process"
  description                = "Detects the creation of a new PowerShell module \".psm1\", \".psd1\", \".dll\", \".ps1\", etc. by a non-PowerShell process"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\WindowsPowerShell\\Modules\\" or FolderPath contains "\\PowerShell\\7\\Modules\\") and (not(((InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")) or (InitiatingProcessFolderPath endswith ":\\Program Files\\PowerShell\\7-preview\\pwsh.exe" or InitiatingProcessFolderPath endswith ":\\Program Files\\PowerShell\\7\\pwsh.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\System32\\poqexec.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\SysWOW64\\poqexec.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell_ise.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}