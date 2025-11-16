resource "azurerm_sentinel_alert_rule_scheduled" "sourgum_actor_behaviours" {
  name                       = "sourgum_actor_behaviours"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "SOURGUM Actor Behaviours"
  description                = "Suspicious behaviours related to an actor tracked by Microsoft as SOURGUM"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath contains "windows\\system32\\Physmem.sys" or FolderPath contains "Windows\\system32\\ime\\SHARED\\WimBootConfigurations.ini" or FolderPath contains "Windows\\system32\\ime\\IMEJP\\WimBootConfigurations.ini" or FolderPath contains "Windows\\system32\\ime\\IMETC\\WimBootConfigurations.ini") or ((ProcessCommandLine contains "reg add" and (FolderPath contains "windows\\system32\\filepath2" or FolderPath contains "windows\\system32\\ime")) and (ProcessCommandLine contains "HKEY_LOCAL_MACHINE\\software\\classes\\clsid\\{7c857801-7381-11cf-884d-00aa004b2e24}\\inprocserver32" or ProcessCommandLine contains "HKEY_LOCAL_MACHINE\\software\\classes\\clsid\\{cf4cc405-e2c5-4ddd-b3ce-5e7582d8c9fa}\\inprocserver32"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1546"]
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