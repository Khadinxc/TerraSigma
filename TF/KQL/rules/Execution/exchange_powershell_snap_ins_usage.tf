resource "azurerm_sentinel_alert_rule_scheduled" "exchange_powershell_snap_ins_usage" {
  name                       = "exchange_powershell_snap_ins_usage"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Exchange PowerShell Snap-Ins Usage"
  description                = "Detects adding and using Exchange PowerShell snap-ins to export mailbox data. As seen used by HAFNIUM and APT27"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Add-PSSnapin" and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll"))) and (ProcessCommandLine contains "Microsoft.Exchange.Powershell.Snapin" or ProcessCommandLine contains "Microsoft.Exchange.Management.PowerShell.SnapIn")) and (not((ProcessCommandLine contains "$exserver=Get-ExchangeServer ([Environment]::MachineName) -ErrorVariable exerr 2> $null" and InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\msiexec.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "Collection"]
  techniques                 = ["T1059", "T1114"]
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