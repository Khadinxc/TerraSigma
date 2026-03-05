resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_susp_network_command" {
  name                       = "proc_creation_win_susp_network_command"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Network Command"
  description                = <<DESC
    Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_network_command.yml

    False Positives:
    - Administrator, hotline ask to user
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine matches regex "ipconfig\\s+/all" or ProcessCommandLine matches regex "netsh\\s+interface show interface" or ProcessCommandLine matches regex "arp\\s+-a" or ProcessCommandLine matches regex "nbtstat\\s+-n" or ProcessCommandLine matches regex "net\\s+config" or ProcessCommandLine matches regex "route\\s+print"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1016"]
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