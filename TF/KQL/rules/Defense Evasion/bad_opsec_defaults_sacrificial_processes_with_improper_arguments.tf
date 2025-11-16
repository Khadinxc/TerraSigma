resource "azurerm_sentinel_alert_rule_scheduled" "bad_opsec_defaults_sacrificial_processes_with_improper_arguments" {
  name                       = "bad_opsec_defaults_sacrificial_processes_with_improper_arguments"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Bad Opsec Defaults Sacrificial Processes With Improper Arguments"
  description                = "Detects attackers using tooling with bad opsec defaults. E.g. spawning a sacrificial process to inject a capability into the process without taking into account how the process is normally run. One trivial example of this is using rundll32.exe without arguments as a sacrificial process (default in CS, now highlighted by c2lint), running WerFault without arguments (Kraken - credit am0nsec), and other examples. - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine endswith "regasm.exe" and FolderPath endswith "\\regasm.exe") or (ProcessCommandLine endswith "regsvcs.exe" and FolderPath endswith "\\regsvcs.exe") or (ProcessCommandLine endswith "regsvr32.exe" and FolderPath endswith "\\regsvr32.exe") or (ProcessCommandLine endswith "rundll32.exe" and FolderPath endswith "\\rundll32.exe") or (ProcessCommandLine endswith "WerFault.exe" and FolderPath endswith "\\WerFault.exe")) and (not(((ProcessCommandLine endswith "rundll32.exe" and FolderPath endswith "\\rundll32.exe" and InitiatingProcessCommandLine contains "--uninstall " and (InitiatingProcessFolderPath contains "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\Application\\" or InitiatingProcessFolderPath contains "\\AppData\\Local\\Google\\Chrome\\Application\\") and InitiatingProcessFolderPath endswith "\\Installer\\setup.exe") or (ProcessCommandLine endswith "rundll32.exe" and FolderPath endswith "\\rundll32.exe" and InitiatingProcessFolderPath contains "\\AppData\\Local\\Microsoft\\EdgeUpdate\\Install\\{"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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