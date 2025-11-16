resource "azurerm_sentinel_alert_rule_scheduled" "deny_service_access_using_security_descriptor_tampering_via_sc_exe" {
  name                       = "deny_service_access_using_security_descriptor_tampering_via_sc_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Deny Service Access Using Security Descriptor Tampering Via Sc.EXE"
  description                = "Detects suspicious DACL modifications to deny access to a service that affects critical trustees. This can be used to hide services or make them unstoppable."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\sc.exe" or ProcessVersionInfoOriginalFileName =~ "sc.exe") and (ProcessCommandLine contains "sdset" and ProcessCommandLine contains "D;") and (ProcessCommandLine contains ";IU" or ProcessCommandLine contains ";SU" or ProcessCommandLine contains ";BA" or ProcessCommandLine contains ";SY" or ProcessCommandLine contains ";WD")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1543"]
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