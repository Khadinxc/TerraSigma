resource "azurerm_sentinel_alert_rule_scheduled" "weak_or_abused_passwords_in_cli" {
  name                       = "weak_or_abused_passwords_in_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Weak or Abused Passwords In CLI"
  description                = "Detects weak passwords or often abused passwords (seen used by threat actors) via the CLI. An example would be a threat actor creating a new user via the net command and providing the password inline - Legitimate usage of the passwords by users via commandline (should be discouraged) - Other currently unknown false positives"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "123456789" or ProcessCommandLine contains "123123qwE" or ProcessCommandLine contains "Asd123.aaaa" or ProcessCommandLine contains "Decryptme" or ProcessCommandLine contains "P@ssw0rd!" or ProcessCommandLine contains "Pass8080" or ProcessCommandLine contains "password123" or ProcessCommandLine contains "test@202"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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