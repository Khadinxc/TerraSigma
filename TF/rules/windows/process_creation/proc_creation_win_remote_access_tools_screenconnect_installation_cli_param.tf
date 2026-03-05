resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_remote_access_tools_screenconnect_installation_cli_param" {
  name                       = "proc_creation_win_remote_access_tools_screenconnect_installation_cli_param"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - ScreenConnect Installation Execution"
  description                = <<DESC
    Detects ScreenConnect program starts that establish a remote access to a system.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_screenconnect_installation_cli_param.yml

    False Positives:
    - Legitimate use by administrative staff
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "e=Access&" and ProcessCommandLine contains "y=Guest&" and ProcessCommandLine contains "&p=" and ProcessCommandLine contains "&c=" and ProcessCommandLine contains "&k="
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "InitialAccess"]
  techniques                 = ["T1133"]
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
}