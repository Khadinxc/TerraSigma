resource "azurerm_sentinel_alert_rule_scheduled" "file_event_lnx_doas_conf_creation" {
  name                       = "file_event_lnx_doas_conf_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Doas Conf File Creation"
  description                = "Detects the creation of doas.conf file in linux host platform. Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_doas_conf_creation.yml - Unlikely | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_doas_conf_creation.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "/etc/doas.conf"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}