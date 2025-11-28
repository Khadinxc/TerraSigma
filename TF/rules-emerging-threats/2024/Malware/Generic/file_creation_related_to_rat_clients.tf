resource "azurerm_sentinel_alert_rule_scheduled" "file_creation_related_to_rat_clients" {
  name                       = "file_creation_related_to_rat_clients"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "File Creation Related To RAT Clients"
  description                = "File .conf created related to VenomRAT, AsyncRAT and Lummac samples observed in the wild. - Legitimate software creating a file with the same name"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath contains "\\AppData\\Roaming\\" and ((FolderPath contains "\\mydata\\" or FolderPath contains "\\datalogs\\" or FolderPath contains "\\hvnc\\" or FolderPath contains "\\dcrat\\") and (FolderPath endswith "\\datalogs.conf" or FolderPath endswith "\\hvnc.conf" or FolderPath endswith "\\dcrat.conf"))
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