resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_ntlm_authentication_on_the_printer_spooler_service" {
  name                       = "suspicious_ntlm_authentication_on_the_printer_spooler_service"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious NTLM Authentication on the Printer Spooler Service"
  description                = "Detects a privilege elevation attempt by coercing NTLM authentication on the Printer Spooler service"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "spoolss" or ProcessCommandLine contains "srvsvc" or ProcessCommandLine contains "/print/pipe/") and (ProcessCommandLine contains "C:\\windows\\system32\\davclnt.dll,DavSetCookie" and ProcessCommandLine contains "http")) and (FolderPath endswith "\\rundll32.exe" or ProcessVersionInfoOriginalFileName =~ "RUNDLL32.EXE")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "CredentialAccess"]
  techniques                 = ["T1212"]
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