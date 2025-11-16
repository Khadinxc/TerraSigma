resource "azurerm_sentinel_alert_rule_scheduled" "netsh_allow_group_policy_on_microsoft_defender_firewall" {
  name                       = "netsh_allow_group_policy_on_microsoft_defender_firewall"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Netsh Allow Group Policy on Microsoft Defender Firewall"
  description                = "Adversaries may modify system firewalls in order to bypass controls limiting network usage - Legitimate administration activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "advfirewall" and ProcessCommandLine contains "firewall" and ProcessCommandLine contains "set" and ProcessCommandLine contains "rule" and ProcessCommandLine contains "group=" and ProcessCommandLine contains "new" and ProcessCommandLine contains "enable=Yes") and (FolderPath endswith "\\netsh.exe" or ProcessVersionInfoOriginalFileName =~ "netsh.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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