resource "azurerm_sentinel_alert_rule_scheduled" "lace_tempest_file_indicators" {
  name                       = "lace_tempest_file_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Lace Tempest File Indicators"
  description                = "Detects PowerShell script file creation with specific names or suffixes which was seen being used often in PowerShell scripts by FIN7 - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith ":\\Program Files\\SysAidServer\\tomcat\\webapps\\usersfiles\\user.exe" or FolderPath endswith ":\\Program Files\\SysAidServer\\tomcat\\webapps\\usersfiles.war" or FolderPath endswith ":\\Program Files\\SysAidServer\\tomcat\\webapps\\leave") or FolderPath contains ":\\Program Files\\SysAidServer\\tomcat\\webapps\\user."
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}