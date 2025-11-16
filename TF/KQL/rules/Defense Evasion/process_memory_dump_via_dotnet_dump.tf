resource "azurerm_sentinel_alert_rule_scheduled" "process_memory_dump_via_dotnet_dump" {
  name                       = "process_memory_dump_via_dotnet_dump"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Process Memory Dump Via Dotnet-Dump"
  description                = "Detects the execution of \"dotnet-dump\" with the \"collect\" flag. The execution could indicate potential process dumping of critical processes such as LSASS. - Process dumping is the expected behavior of the tool. So false positives are expected in legitimate usage. The PID/Process Name of the process being dumped needs to be investigated"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "collect" and (FolderPath endswith "\\dotnet-dump.exe" or ProcessVersionInfoOriginalFileName =~ "dotnet-dump.dll")
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