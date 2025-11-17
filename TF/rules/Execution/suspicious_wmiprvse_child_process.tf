resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_wmiprvse_child_process" {
  name                       = "suspicious_wmiprvse_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious WmiPrvSE Child Process"
  description                = "Detects suspicious and uncommon child processes of WmiPrvSE"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\wbem\\WmiPrvSE.exe" and ((FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\verclsid.exe" or FolderPath endswith "\\wscript.exe") or ((ProcessCommandLine contains "cscript" or ProcessCommandLine contains "mshta" or ProcessCommandLine contains "powershell" or ProcessCommandLine contains "pwsh" or ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "wscript") and FolderPath endswith "\\cmd.exe")) and (not(((ProcessCommandLine contains "/i " and FolderPath endswith "\\msiexec.exe") or FolderPath endswith "\\WerFault.exe" or FolderPath endswith "\\WmiPrvSE.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1047", "T1204", "T1218"]
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