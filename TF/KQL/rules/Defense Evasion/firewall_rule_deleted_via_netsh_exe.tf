resource "azurerm_sentinel_alert_rule_scheduled" "firewall_rule_deleted_via_netsh_exe" {
  name                       = "firewall_rule_deleted_via_netsh_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Firewall Rule Deleted Via Netsh.EXE"
  description                = "Detects the removal of a port or application rule in the Windows Firewall configuration using netsh - Legitimate administration activity - Software installations and removal"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "firewall" and ProcessCommandLine contains "delete ") and (FolderPath endswith "\\netsh.exe" or ProcessVersionInfoOriginalFileName =~ "netsh.exe")) and (not(((ProcessCommandLine contains "advfirewall firewall delete rule name=\"Avast Antivirus Admin Client\"" and InitiatingProcessFolderPath endswith "\\instup.exe") or (ProcessCommandLine contains "name=Dropbox" and InitiatingProcessFolderPath endswith "\\Dropbox.exe"))))
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