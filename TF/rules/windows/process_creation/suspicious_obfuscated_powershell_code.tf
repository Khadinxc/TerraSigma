resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_obfuscated_powershell_code" {
  name                       = "suspicious_obfuscated_powershell_code"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Obfuscated PowerShell Code"
  description                = "Detects suspicious UTF16 and base64 encoded and often obfuscated PowerShell code often used in command lines"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "IAAtAGIAeABvAHIAIAAwAHgA" or ProcessCommandLine contains "AALQBiAHgAbwByACAAMAB4A" or ProcessCommandLine contains "gAC0AYgB4AG8AcgAgADAAeA" or ProcessCommandLine contains "AC4ASQBuAHYAbwBrAGUAKAApACAAfAAg" or ProcessCommandLine contains "AuAEkAbgB2AG8AawBlACgAKQAgAHwAI" or ProcessCommandLine contains "ALgBJAG4AdgBvAGsAZQAoACkAIAB8AC" or ProcessCommandLine contains "AHsAMQB9AHsAMAB9ACIAIAAtAGYAI" or ProcessCommandLine contains "B7ADEAfQB7ADAAfQAiACAALQBmAC" or ProcessCommandLine contains "AewAxAH0AewAwAH0AIgAgAC0AZgAg" or ProcessCommandLine contains "AHsAMAB9AHsAMwB9ACIAIAAtAGYAI" or ProcessCommandLine contains "B7ADAAfQB7ADMAfQAiACAALQBmAC" or ProcessCommandLine contains "AewAwAH0AewAzAH0AIgAgAC0AZgAg" or ProcessCommandLine contains "AHsAMgB9AHsAMAB9ACIAIAAtAGYAI" or ProcessCommandLine contains "B7ADIAfQB7ADAAfQAiACAALQBmAC" or ProcessCommandLine contains "AewAyAH0AewAwAH0AIgAgAC0AZgAg" or ProcessCommandLine contains "AHsAMQB9AHsAMAB9ACcAIAAtAGYAI" or ProcessCommandLine contains "B7ADEAfQB7ADAAfQAnACAALQBmAC" or ProcessCommandLine contains "AewAxAH0AewAwAH0AJwAgAC0AZgAg" or ProcessCommandLine contains "AHsAMAB9AHsAMwB9ACcAIAAtAGYAI" or ProcessCommandLine contains "B7ADAAfQB7ADMAfQAnACAALQBmAC" or ProcessCommandLine contains "AewAwAH0AewAzAH0AJwAgAC0AZgAg" or ProcessCommandLine contains "AHsAMgB9AHsAMAB9ACcAIAAtAGYAI" or ProcessCommandLine contains "B7ADIAfQB7ADAAfQAnACAALQBmAC" or ProcessCommandLine contains "AewAyAH0AewAwAH0AJwAgAC0AZgAg"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
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