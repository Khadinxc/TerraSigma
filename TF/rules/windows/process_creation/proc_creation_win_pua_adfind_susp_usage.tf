resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_pua_adfind_susp_usage" {
  name                       = "proc_creation_win_pua_adfind_susp_usage"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - AdFind Suspicious Execution"
  description                = <<DESC
    Detects AdFind execution with common flags seen used during attacks

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_pua_adfind_susp_usage.yml

    False Positives:
    - Legitimate admin activity
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "domainlist" or ProcessCommandLine contains "trustdmp" or ProcessCommandLine contains "dcmodes" or ProcessCommandLine contains "adinfo" or ProcessCommandLine contains "-sc dclist" or ProcessCommandLine contains "computer_pwdnotreqd" or ProcessCommandLine contains "objectcategory=" or ProcessCommandLine contains "-subnets -f" or ProcessCommandLine contains "name=\"Domain Admins\"" or ProcessCommandLine contains "-sc u:" or ProcessCommandLine contains "domainncs" or ProcessCommandLine contains "dompol" or ProcessCommandLine contains " oudmp " or ProcessCommandLine contains "subnetdmp" or ProcessCommandLine contains "gpodmp" or ProcessCommandLine contains "fspdmp" or ProcessCommandLine contains "users_noexpire" or ProcessCommandLine contains "computers_active" or ProcessCommandLine contains "computers_pwdnotreqd"
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