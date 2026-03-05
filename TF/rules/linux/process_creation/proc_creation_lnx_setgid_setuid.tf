resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_setgid_setuid" {
  name                       = "proc_creation_lnx_setgid_setuid"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Setuid and Setgid"
  description                = <<DESC
    Detects suspicious change of file privileges with chown and chmod commands

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_setgid_setuid.yml

    False Positives:
    - Legitimate administration activities
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " chmod u+s" or ProcessCommandLine contains " chmod g+s") and ProcessCommandLine contains "chown root"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1548"]
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