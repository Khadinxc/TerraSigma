resource "azurerm_sentinel_alert_rule_scheduled" "aadinternals_powershell_cmdlets_execution_proccesscreation" {
  name                       = "aadinternals_powershell_cmdlets_execution_proccesscreation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "AADInternals PowerShell Cmdlets Execution - ProccessCreation"
  description                = "Detects ADDInternals Cmdlet execution. A tool for administering Azure AD and Office 365. Which can be abused by threat actors to attack Azure AD or Office 365. - Legitimate use of the library for administrative activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Add-AADInt" or ProcessCommandLine contains "ConvertTo-AADInt" or ProcessCommandLine contains "Disable-AADInt" or ProcessCommandLine contains "Enable-AADInt" or ProcessCommandLine contains "Export-AADInt" or ProcessCommandLine contains "Find-AADInt" or ProcessCommandLine contains "Get-AADInt" or ProcessCommandLine contains "Grant-AADInt" or ProcessCommandLine contains "Initialize-AADInt" or ProcessCommandLine contains "Install-AADInt" or ProcessCommandLine contains "Invoke-AADInt" or ProcessCommandLine contains "Join-AADInt" or ProcessCommandLine contains "New-AADInt" or ProcessCommandLine contains "Open-AADInt" or ProcessCommandLine contains "Read-AADInt" or ProcessCommandLine contains "Register-AADInt" or ProcessCommandLine contains "Remove-AADInt" or ProcessCommandLine contains "Reset-AADInt" or ProcessCommandLine contains "Resolve-AADInt" or ProcessCommandLine contains "Restore-AADInt" or ProcessCommandLine contains "Save-AADInt" or ProcessCommandLine contains "Search-AADInt" or ProcessCommandLine contains "Send-AADInt" or ProcessCommandLine contains "Set-AADInt" or ProcessCommandLine contains "Start-AADInt" or ProcessCommandLine contains "Unprotect-AADInt" or ProcessCommandLine contains "Update-AADInt") and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.Exe", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Reconnaissance", "Discovery", "CredentialAccess", "Impact"]
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