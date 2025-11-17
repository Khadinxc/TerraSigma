resource "azurerm_sentinel_alert_rule_scheduled" "potential_emotet_activity" {
  name                       = "potential_emotet_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Emotet Activity"
  description                = "Detects all Emotet like process executions that are not covered by the more generic rules - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains " -e" and ProcessCommandLine contains " PAA") or ProcessCommandLine contains "JABlAG4AdgA6AHUAcwBlAHIAcAByAG8AZgBpAGwAZQ" or ProcessCommandLine contains "QAZQBuAHYAOgB1AHMAZQByAHAAcgBvAGYAaQBsAGUA" or ProcessCommandLine contains "kAGUAbgB2ADoAdQBzAGUAcgBwAHIAbwBmAGkAbABlA" or ProcessCommandLine contains "IgAoACcAKgAnACkAOwAkA" or ProcessCommandLine contains "IAKAAnACoAJwApADsAJA" or ProcessCommandLine contains "iACgAJwAqACcAKQA7ACQA" or ProcessCommandLine contains "JABGAGwAeAByAGgAYwBmAGQ" or ProcessCommandLine contains "PQAkAGUAbgB2ADoAdABlAG0AcAArACgA" or ProcessCommandLine contains "0AJABlAG4AdgA6AHQAZQBtAHAAKwAoA" or ProcessCommandLine contains "9ACQAZQBuAHYAOgB0AGUAbQBwACsAKA") and (not((ProcessCommandLine contains "fAAgAEMAbwBuAHYAZQByAHQAVABvAC0ASgBzAG8AbgAgAC0ARQByAHIAbwByAEEAYwB0AGkAbwBuACAAUwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQ" or ProcessCommandLine contains "wAIABDAG8AbgB2AGUAcgB0AFQAbwAtAEoAcwBvAG4AIAAtAEUAcgByAG8AcgBBAGMAdABpAG8AbgAgAFMAaQBsAGUAbgB0AGwAeQBDAG8AbgB0AGkAbgB1AGUA" or ProcessCommandLine contains "8ACAAQwBvAG4AdgBlAHIAdABUAG8ALQBKAHMAbwBuACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAGkAbABlAG4AdABsAHkAQwBvAG4AdABpAG4AdQBlA")))
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