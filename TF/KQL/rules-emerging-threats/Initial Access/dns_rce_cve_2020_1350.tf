resource "azurerm_sentinel_alert_rule_scheduled" "dns_rce_cve_2020_1350" {
  name                       = "dns_rce_cve_2020_1350"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DNS RCE CVE-2020-1350"
  description                = "Detects exploitation of DNS RCE bug reported in CVE-2020-1350 by the detection of suspicious sub process - Unknown but benign sub processes of the Windows DNS service dns.exe"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\System32\\dns.exe" and (not((FolderPath endswith "\\System32\\werfault.exe" or FolderPath endswith "\\System32\\conhost.exe" or FolderPath endswith "\\System32\\dnscmd.exe" or FolderPath endswith "\\System32\\dns.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Execution"]
  techniques                 = ["T1190", "T1569"]
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