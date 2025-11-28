resource "azurerm_sentinel_alert_rule_scheduled" "persistence_via_cron_files" {
  name                       = "persistence_via_cron_files"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Persistence Via Cron Files"
  description                = "Detects creation of cron file or files in Cron directories which could indicates potential persistence. - Any legitimate cron file."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath startswith "/etc/cron.d/" or FolderPath startswith "/etc/cron.daily/" or FolderPath startswith "/etc/cron.hourly/" or FolderPath startswith "/etc/cron.monthly/" or FolderPath startswith "/etc/cron.weekly/" or FolderPath startswith "/var/spool/cron/crontabs/") or (FolderPath contains "/etc/cron.allow" or FolderPath contains "/etc/cron.deny" or FolderPath contains "/etc/crontab")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053"]
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