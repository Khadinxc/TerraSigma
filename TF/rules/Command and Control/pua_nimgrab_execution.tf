resource "azurerm_sentinel_alert_rule_scheduled" "pua_nimgrab_execution" {
  name                       = "pua_nimgrab_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Nimgrab Execution"
  description                = "Detects the usage of nimgrab, a tool bundled with the Nim programming framework and used for downloading files. - Legitimate use of Nim on a developer systems"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (MD5 startswith "2DD44C3C29D667F5C0EF5F9D7C7FFB8B" or SHA256 startswith "F266609E91985F0FE3E31C5E8FAEEEC4FFA5E0322D8B6F15FE69F4C5165B9559") or FolderPath endswith "\\nimgrab.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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