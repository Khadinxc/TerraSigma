resource "azurerm_sentinel_alert_rule_scheduled" "windows_defender_context_menu_removed" {
  name                       = "windows_defender_context_menu_removed"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Defender Context Menu Removed"
  description                = "Detects the use of reg.exe or PowerShell to delete the Windows Defender context menu handler registry keys. This action removes the \"Scan with Microsoft Defender\" option from the right-click menu for files, directories, and drives. Attackers may use this technique to hinder manual, on-demand scans and reduce the visibility of the security product. - May be part of a system customization or \"debloating\" script, but this is highly unusual in a managed corporate environment."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "del" or ProcessCommandLine contains "Remove-Item" or ProcessCommandLine contains "ri ") and ((FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\reg.exe") or (ProcessVersionInfoOriginalFileName in~ ("powershell_ise.EXE", "PowerShell.EXE", "pwsh.dll", "reg.exe"))) and ProcessCommandLine contains "\\shellex\\ContextMenuHandlers\\EPP"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}