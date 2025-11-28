resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_wmic_execution_via_office_process" {
  name                       = "suspicious_wmic_execution_via_office_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious WMIC Execution Via Office Process"
  description                = "Office application called wmic to proxye execution through a LOLBIN process. This is often used to break suspicious parent-child chain (Office app spawns LOLBin)."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith "\\WINWORD.EXE" or InitiatingProcessFolderPath endswith "\\EXCEL.EXE" or InitiatingProcessFolderPath endswith "\\POWERPNT.exe" or InitiatingProcessFolderPath endswith "\\MSPUB.exe" or InitiatingProcessFolderPath endswith "\\VISIO.exe" or InitiatingProcessFolderPath endswith "\\MSACCESS.EXE" or InitiatingProcessFolderPath endswith "\\EQNEDT32.EXE" or InitiatingProcessFolderPath endswith "\\ONENOTE.EXE" or InitiatingProcessFolderPath endswith "\\wordpad.exe" or InitiatingProcessFolderPath endswith "\\wordview.exe") and ((ProcessCommandLine contains "regsvr32" or ProcessCommandLine contains "rundll32" or ProcessCommandLine contains "msiexec" or ProcessCommandLine contains "mshta" or ProcessCommandLine contains "verclsid" or ProcessCommandLine contains "wscript" or ProcessCommandLine contains "cscript") and (ProcessCommandLine contains "process" and ProcessCommandLine contains "create" and ProcessCommandLine contains "call")) and (FolderPath endswith "\\wbem\\WMIC.exe" or ProcessVersionInfoOriginalFileName =~ "wmic.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1204", "T1047", "T1218"]
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