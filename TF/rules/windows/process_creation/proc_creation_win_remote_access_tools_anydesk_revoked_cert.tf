resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_remote_access_tools_anydesk_revoked_cert" {
  name                       = "proc_creation_win_remote_access_tools_anydesk_revoked_cert"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Remote Access Tool - AnyDesk Execution With Known Revoked Signing Certificate"
  description                = <<DESC
    Detects the execution of an AnyDesk binary with a version prior to 8.0.8. Prior to version 8.0.8, the Anydesk application used a signing certificate that got compromised by threat actors. Use this rule to detect instances of older versions of Anydesk using the compromised certificate This is recommended in order to avoid attackers leveraging the certificate and signing their binaries to bypass detections.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_remote_access_tools_anydesk_revoked_cert.yml

    False Positives:
    - Unlikely
  DESC
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
    entity_type = "Account"
    field_mapping {
      identifier  = "Name"
      column_name = "InitiatingProcessAccountName"
    }
    field_mapping {
      identifier  = "NTDomain"
      column_name = "InitiatingProcessAccountDomain"
    }
    field_mapping {
      identifier  = "Sid"
      column_name = "InitiatingProcessAccountSid"
    }
  }

  entity_mapping {
    entity_type = "Host"
    field_mapping {
      identifier  = "HostName"
      column_name = "DeviceName"
    }
    field_mapping {
      identifier  = "AzureID"
      column_name = "DeviceId"
    }
  }

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
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