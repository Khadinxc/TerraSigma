resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_file_created_in_perflogs" {
  name                       = "suspicious_file_created_in_perflogs"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious File Created In PerfLogs"
  description                = "Detects suspicious file based on their extension being created in \"C:\\PerfLogs\\\". Note that this directory mostly contains \".etl\" files - Unlikely"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith ".7z" or FolderPath endswith ".bat" or FolderPath endswith ".bin" or FolderPath endswith ".chm" or FolderPath endswith ".dll" or FolderPath endswith ".exe" or FolderPath endswith ".hta" or FolderPath endswith ".lnk" or FolderPath endswith ".ps1" or FolderPath endswith ".psm1" or FolderPath endswith ".py" or FolderPath endswith ".scr" or FolderPath endswith ".sys" or FolderPath endswith ".vbe" or FolderPath endswith ".vbs" or FolderPath endswith ".zip") and FolderPath startswith "C:\\PerfLogs\\"
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}