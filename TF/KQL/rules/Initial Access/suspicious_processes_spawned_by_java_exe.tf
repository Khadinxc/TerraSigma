resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_processes_spawned_by_java_exe" {
  name                       = "suspicious_processes_spawned_by_java_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Processes Spawned by Java.EXE"
  description                = "Detects suspicious processes spawned from a Java host process which could indicate a sign of exploitation (e.g. log4j) - Legitimate calls to system binaries - Company specific internal usage"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\AppVLP.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\curl.exe" or FolderPath endswith "\\forfiles.exe" or FolderPath endswith "\\hh.exe" or FolderPath endswith "\\mftrace.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\net.exe" or FolderPath endswith "\\net1.exe" or FolderPath endswith "\\query.exe" or FolderPath endswith "\\reg.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\scrcons.exe" or FolderPath endswith "\\scriptrunner.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\systeminfo.exe" or FolderPath endswith "\\whoami.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\wscript.exe") and InitiatingProcessFolderPath endswith "\\java.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Persistence", "PrivilegeEscalation"]
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