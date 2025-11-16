resource "azurerm_sentinel_alert_rule_scheduled" "enable_lm_hash_storage_proccreation" {
  name                       = "enable_lm_hash_storage_proccreation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Enable LM Hash Storage - ProcCreation"
  description                = "Detects changes to the \"NoLMHash\" registry value in order to allow Windows to store LM Hashes. By setting this registry value to \"0\" (DWORD), Windows will be allowed to store a LAN manager hash of your password in Active Directory and local SAM databases."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\System\\CurrentControlSet\\Control\\Lsa" and ProcessCommandLine contains "NoLMHash" and ProcessCommandLine contains " 0"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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
  }
}