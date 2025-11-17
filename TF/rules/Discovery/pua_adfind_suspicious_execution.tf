resource "azurerm_sentinel_alert_rule_scheduled" "pua_adfind_suspicious_execution" {
  name                       = "pua_adfind_suspicious_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - AdFind Suspicious Execution"
  description                = "Detects AdFind execution with common flags seen used during attacks - Legitimate admin activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "domainlist" or ProcessCommandLine contains "trustdmp" or ProcessCommandLine contains "dcmodes" or ProcessCommandLine contains "adinfo" or ProcessCommandLine contains " dclist " or ProcessCommandLine contains "computer_pwdnotreqd" or ProcessCommandLine contains "objectcategory=" or ProcessCommandLine contains "-subnets -f" or ProcessCommandLine contains "name=\"Domain Admins\"" or ProcessCommandLine contains "-sc u:" or ProcessCommandLine contains "domainncs" or ProcessCommandLine contains "dompol" or ProcessCommandLine contains " oudmp " or ProcessCommandLine contains "subnetdmp" or ProcessCommandLine contains "gpodmp" or ProcessCommandLine contains "fspdmp" or ProcessCommandLine contains "users_noexpire" or ProcessCommandLine contains "computers_active" or ProcessCommandLine contains "computers_pwdnotreqd"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1018", "T1087", "T1482", "T1069"]
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