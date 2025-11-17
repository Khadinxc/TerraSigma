resource "azurerm_sentinel_alert_rule_scheduled" "execute_from_alternate_data_streams" {
  name                       = "execute_from_alternate_data_streams"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Execute From Alternate Data Streams"
  description                = "Detects execution from an Alternate Data Stream (ADS). Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "txt:" and ((ProcessCommandLine contains "esentutl " and ProcessCommandLine contains " /y " and ProcessCommandLine contains " /d " and ProcessCommandLine contains " /o ") or (ProcessCommandLine contains "makecab " and ProcessCommandLine contains ".cab") or (ProcessCommandLine contains "reg " and ProcessCommandLine contains " export ") or (ProcessCommandLine contains "regedit " and ProcessCommandLine contains " /E ") or (ProcessCommandLine contains "type " and ProcessCommandLine contains " > "))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1564"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}