resource "azurerm_sentinel_alert_rule_scheduled" "qakbot_uninstaller_execution" {
  name                       = "qakbot_uninstaller_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Qakbot Uninstaller Execution"
  description                = "Detects the execution of the Qakbot uninstaller file mentioned in the USAO-CDCA document on the disruption of the Qakbot malware and botnet - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\QbotUninstall.exe" or (SHA256 startswith "423A9D13D410E2DC38EABB9FDF3121D2072472D0426260283A638B822DCD5180" or SHA256 startswith "559CAE635F0D870652B9482EF436B31D4BB1A5A0F51750836F328D749291D0B6" or SHA256 startswith "855EB5481F77DDE5AD8FA6E9D953D4AEBC280DDDF9461144B16ED62817CC5071" or SHA256 startswith "FAB408536AA37C4ABC8BE97AB9C1F86CB33B63923D423FDC2859EB9D63FA8EA0")
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