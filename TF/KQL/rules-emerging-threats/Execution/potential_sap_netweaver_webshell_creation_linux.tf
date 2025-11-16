resource "azurerm_sentinel_alert_rule_scheduled" "potential_sap_netweaver_webshell_creation_linux" {
  name                       = "potential_sap_netweaver_webshell_creation_linux"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential SAP NetWeaver Webshell Creation - Linux"
  description                = "Detects the creation of suspicious files (jsp, java, class) in SAP NetWeaver directories, which may indicate exploitation attempts of vulnerabilities such as CVE-2025-31324. - Legitimate creation of jsc or java files in these locations"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath endswith ".jsp" or FolderPath endswith ".java" or FolderPath endswith ".class") and (FolderPath contains "/j2ee/cluster/apps/sap.com/irj/servlet_jsp/irj/work/" or FolderPath contains "/j2ee/cluster/apps/sap.com/irj/servlet_jsp/irj/root/")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "InitialAccess", "Persistence"]
  techniques                 = ["T1190", "T1059"]
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