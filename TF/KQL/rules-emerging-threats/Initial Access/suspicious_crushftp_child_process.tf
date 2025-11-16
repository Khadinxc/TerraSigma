resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_crushftp_child_process" {
  name                       = "suspicious_crushftp_child_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious CrushFTP Child Process"
  description                = "Detects suspicious child processes spawned by the CrushFTP service that may indicate exploitation of remote code execution vulnerabilities such as CVE-2025-31161, where attackers can achieve RCE through crafted HTTP requests. The detection focuses on commonly abused Windows executables (like powershell.exe, cmd.exe etc.) that attackers typically use post-exploitation to execute malicious commands. - Legitimate CrushFTP administrative actions - Software updates"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\bash.exe" or FolderPath endswith "\\cmd.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\powershell_ise.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\sh.exe" or FolderPath endswith "\\wscript.exe") and InitiatingProcessFolderPath endswith "\\crushftpservice.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Execution"]
  techniques                 = ["T1059", "T1190"]
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