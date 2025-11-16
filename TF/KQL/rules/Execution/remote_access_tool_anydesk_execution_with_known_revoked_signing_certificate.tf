resource "azurerm_sentinel_alert_rule_scheduled" "remote_access_tool_anydesk_execution_with_known_revoked_signing_certificate" {
  name                       = "remote_access_tool_anydesk_execution_with_known_revoked_signing_certificate"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - AnyDesk Execution With Known Revoked Signing Certificate"
  description                = "Detects the execution of an AnyDesk binary with a version prior to 8.0.8. Prior to version 8.0.8, the Anydesk application used a signing certificate that got compromised by threat actors. Use this rule to detect instances of older versions of Anydesk using the compromised certificate This is recommended in order to avoid attackers leveraging the certificate and signing their binaries to bypass detections. - Unlikely"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((FolderPath endswith "\\AnyDesk.exe" or ProcessVersionInfoFileDescription =~ "AnyDesk" or ProcessVersionInfoProductName =~ "AnyDesk" or ProcessVersionInfoCompanyName =~ "AnyDesk Software GmbH") and (ProcessVersionInfoProductVersion startswith "7.0." or ProcessVersionInfoProductVersion startswith "7.1." or ProcessVersionInfoProductVersion startswith "8.0.1" or ProcessVersionInfoProductVersion startswith "8.0.2" or ProcessVersionInfoProductVersion startswith "8.0.3" or ProcessVersionInfoProductVersion startswith "8.0.4" or ProcessVersionInfoProductVersion startswith "8.0.5" or ProcessVersionInfoProductVersion startswith "8.0.6" or ProcessVersionInfoProductVersion startswith "8.0.7")) and (not((ProcessCommandLine contains " --remove" or ProcessCommandLine contains " --uninstall")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "InitialAccess"]
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