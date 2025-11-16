resource "azurerm_sentinel_alert_rule_scheduled" "xsl_script_execution_via_wmic_exe" {
  name                       = "xsl_script_execution_via_wmic_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "XSL Script Execution Via WMIC.EXE"
  description                = "Detects the execution of WMIC with the \"format\" flag to potentially load XSL files. Adversaries abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. - WMIC.exe FP depend on scripts and administrative methods used in the monitored environment. - Static format arguments - https://petri.com/command-line-wmi-part-3"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "-format" or ProcessCommandLine contains "/format" or ProcessCommandLine contains "–format" or ProcessCommandLine contains "—format" or ProcessCommandLine contains "―format") and FolderPath endswith "\\wmic.exe") and (not((ProcessCommandLine contains "Format:List" or ProcessCommandLine contains "Format:htable" or ProcessCommandLine contains "Format:hform" or ProcessCommandLine contains "Format:table" or ProcessCommandLine contains "Format:mof" or ProcessCommandLine contains "Format:value" or ProcessCommandLine contains "Format:rawxml" or ProcessCommandLine contains "Format:xml" or ProcessCommandLine contains "Format:csv")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1220"]
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