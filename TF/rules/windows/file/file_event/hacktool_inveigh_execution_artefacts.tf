resource "azurerm_sentinel_alert_rule_scheduled" "hacktool_inveigh_execution_artefacts" {
  name                       = "hacktool_inveigh_execution_artefacts"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "HackTool - Inveigh Execution Artefacts"
  description                = "Detects the presence and execution of Inveigh via dropped artefacts - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\Inveigh-Log.txt" or FolderPath endswith "\\Inveigh-Cleartext.txt" or FolderPath endswith "\\Inveigh-NTLMv1Users.txt" or FolderPath endswith "\\Inveigh-NTLMv2Users.txt" or FolderPath endswith "\\Inveigh-NTLMv1.txt" or FolderPath endswith "\\Inveigh-NTLMv2.txt" or FolderPath endswith "\\Inveigh-FormInput.txt" or FolderPath endswith "\\Inveigh.dll" or FolderPath endswith "\\Inveigh.exe" or FolderPath endswith "\\Inveigh.ps1" or FolderPath endswith "\\Inveigh-Relay.ps1"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1219"]
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