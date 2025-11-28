resource "azurerm_sentinel_alert_rule_scheduled" "potential_binary_or_script_dropper_via_powershell" {
  name                       = "potential_binary_or_script_dropper_via_powershell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Binary Or Script Dropper Via PowerShell"
  description                = "Detects PowerShell creating a binary executable or a script file."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where ((InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\powershell_ise.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe") and (FolderPath endswith ".bat" or FolderPath endswith ".chm" or FolderPath endswith ".cmd" or FolderPath endswith ".com" or FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".hta" or FolderPath endswith ".jar" or FolderPath endswith ".js" or FolderPath endswith ".ocx" or FolderPath endswith ".scr" or FolderPath endswith ".sys" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs" or FolderPath endswith ".wsf")) and (not(((FolderPath endswith "\\Microsoft.PackageManagement.NuGetProvider.dll" and FolderPath startswith "C:\\Program Files\\PackageManagement\\ProviderAssemblies\\nuget\\") or ((FolderPath endswith ".dll" or FolderPath endswith ".exe") and (FolderPath startswith "C:\\Windows\\Temp\\" or FolderPath startswith "C:\\Windows\\SystemTemp\\")) or (FolderPath contains "\\WindowsPowerShell\\Modules\\" and FolderPath endswith ".dll" and FolderPath startswith "C:\\Users\\") or (FolderPath contains "\\AppData\\Local\\Temp\\" and (FolderPath endswith ".dll" or FolderPath endswith ".exe") and FolderPath startswith "C:\\Users\\"))))
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