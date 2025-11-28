resource "azurerm_sentinel_alert_rule_scheduled" "potential_sam_database_dump" {
  name                       = "potential_sam_database_dump"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential SAM Database Dump"
  description                = "Detects the creation of files that look like exports of the local SAM (Security Account Manager) - Rare cases of administrative activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith "\\Temp\\sam" or FolderPath endswith "\\sam.sav" or FolderPath endswith "\\Intel\\sam" or FolderPath endswith "\\sam.hive" or FolderPath endswith "\\Perflogs\\sam" or FolderPath endswith "\\ProgramData\\sam" or FolderPath endswith "\\Users\\Public\\sam" or FolderPath endswith "\\AppData\\Local\\sam" or FolderPath endswith "\\AppData\\Roaming\\sam" or FolderPath endswith "_ShadowSteal.zip" or FolderPath endswith "\\Documents\\SAM.export" or FolderPath endswith ":\\sam") or (FolderPath contains "\\hive_sam_" or FolderPath contains "\\sam.save" or FolderPath contains "\\sam.export" or FolderPath contains "\\~reg_sam.save" or FolderPath contains "\\sam_backup" or FolderPath contains "\\sam.bck" or FolderPath contains "\\sam.backup")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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