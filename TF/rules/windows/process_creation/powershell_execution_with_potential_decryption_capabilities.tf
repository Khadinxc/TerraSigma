resource "azurerm_sentinel_alert_rule_scheduled" "powershell_execution_with_potential_decryption_capabilities" {
  name                       = "powershell_execution_with_potential_decryption_capabilities"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Execution With Potential Decryption Capabilities"
  description                = "Detects PowerShell commands that decrypt an \".LNK\" \"file to drop the next stage of the malware. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "Get-ChildItem " or ProcessCommandLine contains "dir " or ProcessCommandLine contains "gci " or ProcessCommandLine contains "ls ") and (ProcessCommandLine contains "Get-Content " or ProcessCommandLine contains "gc " or ProcessCommandLine contains "cat " or ProcessCommandLine contains "type " or ProcessCommandLine contains "ReadAllBytes") and ((ProcessCommandLine contains " ^| " and ProcessCommandLine contains "*.lnk" and ProcessCommandLine contains "-Recurse" and ProcessCommandLine contains "-Skip ") or (ProcessCommandLine contains " -ExpandProperty " and ProcessCommandLine contains "*.lnk" and ProcessCommandLine contains "WriteAllBytes" and ProcessCommandLine contains " .length ")) and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") and (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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