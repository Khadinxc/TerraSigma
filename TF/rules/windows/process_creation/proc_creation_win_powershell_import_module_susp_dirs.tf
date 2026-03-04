resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_powershell_import_module_susp_dirs" {
  name                       = "proc_creation_win_powershell_import_module_susp_dirs"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Import PowerShell Modules From Suspicious Directories - ProcCreation"
  description                = "Detects powershell scripts that import modules from suspicious directories Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_import_module_susp_dirs.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_powershell_import_module_susp_dirs.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "Import-Module \"$Env:Temp\\" or ProcessCommandLine contains "Import-Module '$Env:Temp\\" or ProcessCommandLine contains "Import-Module $Env:Temp\\" or ProcessCommandLine contains "Import-Module \"$Env:Appdata\\" or ProcessCommandLine contains "Import-Module '$Env:Appdata\\" or ProcessCommandLine contains "Import-Module $Env:Appdata\\" or ProcessCommandLine contains "Import-Module C:\\Users\\Public\\" or ProcessCommandLine contains "ipmo \"$Env:Temp\\" or ProcessCommandLine contains "ipmo '$Env:Temp\\" or ProcessCommandLine contains "ipmo $Env:Temp\\" or ProcessCommandLine contains "ipmo \"$Env:Appdata\\" or ProcessCommandLine contains "ipmo '$Env:Appdata\\" or ProcessCommandLine contains "ipmo $Env:Appdata\\" or ProcessCommandLine contains "ipmo C:\\Users\\Public\\"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
}