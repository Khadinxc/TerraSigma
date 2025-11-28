resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_usage_of_for_loop_with_recursive_directory_search_in_cmd" {
  name                       = "suspicious_usage_of_for_loop_with_recursive_directory_search_in_cmd"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Usage of For Loop with Recursive Directory Search in CMD"
  description                = "Detects suspicious usage of the cmd.exe 'for /f' loop combined with the 'tokens=' parameter and a recursive directory listing. This pattern may indicate an attempt to discover and execute system binaries dynamically, for example powershell, a technique sometimes used by attackers to evade detection. This behavior has been observed in various malicious lnk files."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "for /f" and ProcessCommandLine contains "tokens=" and ProcessCommandLine contains "in (" and ProcessCommandLine contains "dir") or (InitiatingProcessCommandLine contains "for /f" and InitiatingProcessCommandLine contains "tokens=" and InitiatingProcessCommandLine contains "in (" and InitiatingProcessCommandLine contains "dir")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion"]
  techniques                 = ["T1059", "T1027"]
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