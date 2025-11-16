resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_shells_spawn_by_java_utility_keytool" {
  name                       = "suspicious_shells_spawn_by_java_utility_keytool"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious Shells Spawn by Java Utility Keytool"
  description                = "Detects suspicious shell spawn from Java utility keytool process (e.g. adselfservice plus exploitation)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\bash.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\certutil.exe" or FolderPath endswith "\\whoami.exe" or FolderPath endswith "\\bitsadmin.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\scrcons.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\hh.exe" or FolderPath endswith "\\wmic.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\forfiles.exe" or FolderPath endswith "\\scriptrunner.exe" or FolderPath endswith "\\mftrace.exe" or FolderPath endswith "\\AppVLP.exe" or FolderPath endswith "\\systeminfo.exe" or FolderPath endswith "\\reg.exe" or FolderPath endswith "\\query.exe") and InitiatingProcessFolderPath endswith "\\keytool.exe"
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