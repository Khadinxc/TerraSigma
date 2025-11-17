resource "azurerm_sentinel_alert_rule_scheduled" "sql_client_tools_powershell_session_detection" {
  name                       = "sql_client_tools_powershell_session_detection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "SQL Client Tools PowerShell Session Detection"
  description                = "This rule detects execution of a PowerShell code through the sqltoolsps.exe utility, which is included in the standard set of utilities supplied with the Microsoft SQL Server Management studio. Script blocks are not logged in this case, so this utility helps to bypass protection mechanisms based on the analysis of these logs. - Direct PS command execution through SQLToolsPS.exe is uncommon, childprocess sqltoolsps.exe spawned by smss.exe is a legitimate action."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\sqltoolsps.exe" or InitiatingProcessFolderPath endswith "\\sqltoolsps.exe" or ProcessVersionInfoOriginalFileName =~ "\\sqltoolsps.exe") and (not(InitiatingProcessFolderPath endswith "\\smss.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1127"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}