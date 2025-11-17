resource "azurerm_sentinel_alert_rule_scheduled" "office_application_initiated_network_connection_over_uncommon_ports" {
  name                       = "office_application_initiated_network_connection_over_uncommon_ports"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Office Application Initiated Network Connection Over Uncommon Ports"
  description                = "Detects an office suit application (Word, Excel, PowerPoint, Outlook) communicating to target systems over uncommon ports. - Other ports can be used, apply additional filters accordingly"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where (InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\winword.exe" or InitiatingProcessFolderPath endswith "\\wordview.exe") and (not(((RemotePort in~ ("53", "80", "139", "389", "443", "445", "3268")) or ((RemotePort in~ ("143", "465", "587", "993", "995")) and InitiatingProcessFolderPath contains ":\\Program Files\\Microsoft Office\\" and InitiatingProcessFolderPath endswith "\\OUTLOOK.EXE"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CommandAndControl"]
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
    entity_type = "IP"
    field_mapping {
      identifier  = "Address"
      column_name = "RemoteIP"
    }
  }
}