resource "azurerm_sentinel_alert_rule_scheduled" "unc4841_ssl_certificate_exfiltration_via_openssl" {
  name                       = "unc4841_ssl_certificate_exfiltration_via_openssl"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "UNC4841 - SSL Certificate Exfiltration Via Openssl"
  description                = "Detects the execution of \"openssl\" to connect to an IP address. This techniques was used by UNC4841 to exfiltrate SSL certificates and as a C2 channel with named pipes. Investigate commands executed in the temporal vicinity of this command."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains ":443" or ProcessCommandLine contains ":8080") and (ProcessCommandLine contains "s_client" and ProcessCommandLine contains "-quiet" and ProcessCommandLine contains "-connect") and ProcessCommandLine matches regex "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}" and FolderPath endswith "/openssl"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1140"]
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