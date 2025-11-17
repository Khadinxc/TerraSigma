resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_process_spawned_by_centrestack_portal_apppool" {
  name                       = "suspicious_process_spawned_by_centrestack_portal_apppool"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Process Spawned by CentreStack Portal AppPool"
  description                = "Detects unexpected command shell execution (cmd.exe) from w3wp.exe when tied to CentreStack's portal.config, indicating potential exploitation (e.g., CVE-2025-30406) - Potentially if other portal services run on w3wp with a apppool\\portal\\portal.config, if you want to increase scope you could add user IIS APPPOOL\\portal."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\cmd.exe" and InitiatingProcessCommandLine contains "\\portal\\portal.config" and InitiatingProcessFolderPath endswith "\\w3wp.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "Execution"]
  techniques                 = ["T1059", "T1505"]
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

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}