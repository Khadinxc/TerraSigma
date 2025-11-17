resource "azurerm_sentinel_alert_rule_scheduled" "regsvr32_execution_from_highly_suspicious_location" {
  name                       = "regsvr32_execution_from_highly_suspicious_location"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Regsvr32 Execution From Highly Suspicious Location"
  description                = "Detects execution of regsvr32 where the DLL is located in a highly suspicious locations - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\regsvr32.exe" or ProcessVersionInfoOriginalFileName =~ "REGSVR32.EXE") and ((ProcessCommandLine contains ":\\PerfLogs\\" or ProcessCommandLine contains ":\\Temp\\" or ProcessCommandLine contains "\\Windows\\Registration\\CRMLog" or ProcessCommandLine contains "\\Windows\\System32\\com\\dmp\\" or ProcessCommandLine contains "\\Windows\\System32\\FxsTmp\\" or ProcessCommandLine contains "\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\" or ProcessCommandLine contains "\\Windows\\System32\\spool\\drivers\\color\\" or ProcessCommandLine contains "\\Windows\\System32\\spool\\PRINTERS\\" or ProcessCommandLine contains "\\Windows\\System32\\spool\\SERVERS\\" or ProcessCommandLine contains "\\Windows\\System32\\Tasks_Migrated\\" or ProcessCommandLine contains "\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter\\" or ProcessCommandLine contains "\\Windows\\SysWOW64\\com\\dmp\\" or ProcessCommandLine contains "\\Windows\\SysWOW64\\FxsTmp\\" or ProcessCommandLine contains "\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System\\" or ProcessCommandLine contains "\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter\\" or ProcessCommandLine contains "\\Windows\\Tasks\\" or ProcessCommandLine contains "\\Windows\\Tracing\\") or ((ProcessCommandLine contains " \"C:\\" or ProcessCommandLine contains " C:\\" or ProcessCommandLine contains " 'C:\\" or ProcessCommandLine contains "D:\\") and (not((ProcessCommandLine contains "C:\\Program Files (x86)\\" or ProcessCommandLine contains "C:\\Program Files\\" or ProcessCommandLine contains "C:\\ProgramData\\" or ProcessCommandLine contains "C:\\Users\\" or ProcessCommandLine contains " C:\\Windows\\" or ProcessCommandLine contains " \"C:\\Windows\\" or ProcessCommandLine contains " 'C:\\Windows\\"))))) and (not((ProcessCommandLine =~ "" or isnull(ProcessCommandLine))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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