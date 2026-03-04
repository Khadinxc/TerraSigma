resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_base64_shebang_cli" {
  name                       = "proc_creation_lnx_base64_shebang_cli"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Linux Base64 Encoded Shebang In CLI"
  description                = "Detects the presence of a base64 version of the shebang in the commandline, which could indicate a malicious payload about to be decoded Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_base64_shebang_cli.yml - Legitimate administration activities | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_base64_shebang_cli.yml"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "IyEvYmluL2Jhc2" or ProcessCommandLine contains "IyEvYmluL2Rhc2" or ProcessCommandLine contains "IyEvYmluL3pza" or ProcessCommandLine contains "IyEvYmluL2Zpc2" or ProcessCommandLine contains "IyEvYmluL3No"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1140"]
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