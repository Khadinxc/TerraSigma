resource "azurerm_sentinel_alert_rule_scheduled" "firewall_disabled_via_netsh_exe" {
  name                       = "firewall_disabled_via_netsh_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Firewall Disabled via Netsh.EXE"
  description                = "Detects netsh commands that turns off the Windows firewall - Legitimate administration activity"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\netsh.exe" or ProcessVersionInfoOriginalFileName =~ "netsh.exe") and ((ProcessCommandLine contains "firewall" and ProcessCommandLine contains "set" and ProcessCommandLine contains "opmode" and ProcessCommandLine contains "disable") or (ProcessCommandLine contains "advfirewall" and ProcessCommandLine contains "set" and ProcessCommandLine contains "state" and ProcessCommandLine contains "off"))
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