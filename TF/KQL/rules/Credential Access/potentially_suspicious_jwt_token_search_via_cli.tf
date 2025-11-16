resource "azurerm_sentinel_alert_rule_scheduled" "potentially_suspicious_jwt_token_search_via_cli" {
  name                       = "potentially_suspicious_jwt_token_search_via_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potentially Suspicious JWT Token Search Via CLI"
  description                = "Detects potentially suspicious search for JWT tokens via CLI by looking for the string \"eyJ0eX\" or \"eyJhbG\". JWT tokens are often used for access-tokens across various applications and services like Microsoft 365, Azure, AWS, Google Cloud, and others. Threat actors may search for these tokens to steal them for lateral movement or privilege escalation."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "eyJ0eXAiOi" or ProcessCommandLine contains "eyJhbGciOi" or ProcessCommandLine contains " eyJ0eX" or ProcessCommandLine contains " \"eyJ0eX\"" or ProcessCommandLine contains " 'eyJ0eX'" or ProcessCommandLine contains " eyJhbG" or ProcessCommandLine contains " \"eyJhbG\"" or ProcessCommandLine contains " 'eyJhbG'") and (ProcessCommandLine contains "find " or ProcessCommandLine contains "find.exe" or ProcessCommandLine contains "findstr" or ProcessCommandLine contains "select-string " or ProcessCommandLine contains "strings")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1528", "T1552"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}