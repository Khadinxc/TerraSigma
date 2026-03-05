resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_net_stop_service" {
  name                       = "proc_creation_win_net_stop_service"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Stop Windows Service Via Net.EXE"
  description                = <<DESC
    Detects the stopping of a Windows service via the "net" utility.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_net_stop_service.yml

    False Positives:
    - There are many legitimate reasons to stop a service. This rule isn't looking for any suspicious behaviour in particular. Filter legitimate activity accordingly
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains " stop " and ((ProcessVersionInfoOriginalFileName in~ ("net.exe", "net1.exe")) or (FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Impact"]
  techniques                 = ["T1489"]
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

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}