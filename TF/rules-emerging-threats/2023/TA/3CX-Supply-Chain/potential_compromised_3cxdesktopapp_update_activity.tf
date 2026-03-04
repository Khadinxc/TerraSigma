resource "azurerm_sentinel_alert_rule_scheduled" "potential_compromised_3cxdesktopapp_update_activity" {
  name                       = "potential_compromised_3cxdesktopapp_update_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Compromised 3CXDesktopApp Update Activity"
  description                = "Detects the 3CXDesktopApp updater downloading a known compromised version of the 3CXDesktopApp software | Source: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2023/TA/3CX-Supply-Chain/potential_compromised_3cxdesktopapp_update_activity.tf"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "--update" and ProcessCommandLine contains "http" and ProcessCommandLine contains "/electron/update/win32/18.12") and FolderPath endswith "\\3CXDesktopApp\\app\\update.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1218"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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