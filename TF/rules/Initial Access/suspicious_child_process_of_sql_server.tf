resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_child_process_of_sql_server" {
  name                       = "suspicious_child_process_of_sql_server"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Child Process Of SQL Server"
  description                = "Detects suspicious child processes of the SQLServer process. This could indicate potential RCE or SQL Injection."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\bash.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\netstat.exe" or FolderPath endswith "\\nltest.exe" or FolderPath endswith "\\ping.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\systeminfo.exe" or FolderPath endswith "\\tasklist.exe" or FolderPath endswith "\\wsl.exe") and InitiatingProcessFolderPath endswith "\\sqlservr.exe") and (not((ProcessCommandLine startswith "\"C:\\Windows\\system32\\cmd.exe\" " and FolderPath =~ "C:\\Windows\\System32\\cmd.exe" and InitiatingProcessFolderPath endswith "DATEV_DBENGINE\\MSSQL\\Binn\\sqlservr.exe" and InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft SQL Server\\")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1505", "T1190"]
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