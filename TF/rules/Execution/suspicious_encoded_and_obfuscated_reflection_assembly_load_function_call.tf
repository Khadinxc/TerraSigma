resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_encoded_and_obfuscated_reflection_assembly_load_function_call" {
  name                       = "suspicious_encoded_and_obfuscated_reflection_assembly_load_function_call"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Encoded And Obfuscated Reflection Assembly Load Function Call"
  description                = "Detects suspicious base64 encoded and obfuscated \"LOAD\" keyword used in .NET \"reflection.assembly\" - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "OgA6ACgAIgBMACIAKwAiAG8AYQBkACIAKQ" or ProcessCommandLine contains "oAOgAoACIATAAiACsAIgBvAGEAZAAiACkA" or ProcessCommandLine contains "6ADoAKAAiAEwAIgArACIAbwBhAGQAIgApA" or ProcessCommandLine contains "OgA6ACgAIgBMAG8AIgArACIAYQBkACIAKQ" or ProcessCommandLine contains "oAOgAoACIATABvACIAKwAiAGEAZAAiACkA" or ProcessCommandLine contains "6ADoAKAAiAEwAbwAiACsAIgBhAGQAIgApA" or ProcessCommandLine contains "OgA6ACgAIgBMAG8AYQAiACsAIgBkACIAKQ" or ProcessCommandLine contains "oAOgAoACIATABvAGEAIgArACIAZAAiACkA" or ProcessCommandLine contains "6ADoAKAAiAEwAbwBhACIAKwAiAGQAIgApA" or ProcessCommandLine contains "OgA6ACgAJwBMACcAKwAnAG8AYQBkACcAKQ" or ProcessCommandLine contains "oAOgAoACcATAAnACsAJwBvAGEAZAAnACkA" or ProcessCommandLine contains "6ADoAKAAnAEwAJwArACcAbwBhAGQAJwApA" or ProcessCommandLine contains "OgA6ACgAJwBMAG8AJwArACcAYQBkACcAKQ" or ProcessCommandLine contains "oAOgAoACcATABvACcAKwAnAGEAZAAnACkA" or ProcessCommandLine contains "6ADoAKAAnAEwAbwAnACsAJwBhAGQAJwApA" or ProcessCommandLine contains "OgA6ACgAJwBMAG8AYQAnACsAJwBkACcAKQ" or ProcessCommandLine contains "oAOgAoACcATABvAGEAJwArACcAZAAnACkA" or ProcessCommandLine contains "6ADoAKAAnAEwAbwBhACcAKwAnAGQAJwApA"
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