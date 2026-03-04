resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_driverquery_recon" {
  name                       = "proc_creation_win_driverquery_recon"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Recon Activity Using DriverQuery.EXE"
  description                = "Detect usage of the \"driverquery\" utility to perform reconnaissance on installed drivers Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_driverquery_recon.yml - Legitimate usage by some scripts might trigger this as well | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_driverquery_recon.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "driverquery.exe" or ProcessVersionInfoOriginalFileName =~ "drvqry.exe") and ((InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe") or (InitiatingProcessFolderPath contains "\\AppData\\Local\\" or InitiatingProcessFolderPath contains "\\Users\\Public\\" or InitiatingProcessFolderPath contains "\\Windows\\Temp\\"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
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