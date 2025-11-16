resource "azurerm_sentinel_alert_rule_scheduled" "potential_php_reverse_shell" {
  name                       = "potential_php_reverse_shell"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential PHP Reverse Shell"
  description                = "Detects usage of the PHP CLI with the \"-r\" flag which allows it to run inline PHP code. The rule looks for calls to the \"fsockopen\" function which allows the creation of sockets. Attackers often leverage this in combination with functions such as \"exec\" or \"fopen\" to initiate a reverse shell connection."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "ash" or ProcessCommandLine contains "bash" or ProcessCommandLine contains "bsh" or ProcessCommandLine contains "csh" or ProcessCommandLine contains "ksh" or ProcessCommandLine contains "pdksh" or ProcessCommandLine contains "sh" or ProcessCommandLine contains "tcsh" or ProcessCommandLine contains "zsh") and (ProcessCommandLine contains " -r " and ProcessCommandLine contains "fsockopen") and FolderPath contains "/php"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
    }
  }

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}