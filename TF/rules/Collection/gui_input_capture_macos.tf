resource "azurerm_sentinel_alert_rule_scheduled" "gui_input_capture_macos" {
  name                       = "gui_input_capture_macos"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "GUI Input Capture - macOS"
  description                = "Detects attempts to use system dialog prompts to capture user credentials - Legitimate administration tools and activities"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath =~ "/usr/sbin/osascript" and (ProcessCommandLine contains "-e" and ProcessCommandLine contains "display" and ProcessCommandLine contains "dialog" and ProcessCommandLine contains "answer") and (ProcessCommandLine contains "admin" or ProcessCommandLine contains "administrator" or ProcessCommandLine contains "authenticate" or ProcessCommandLine contains "authentication" or ProcessCommandLine contains "credentials" or ProcessCommandLine contains "pass" or ProcessCommandLine contains "password" or ProcessCommandLine contains "unlock")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "CredentialAccess"]
  techniques                 = ["T1056"]
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
    field_mapping {
      identifier  = "UPNSuffix"
      column_name = "InitiatingProcessAccountUpn"
    }
    field_mapping {
      identifier  = "AadUserId"
      column_name = "InitiatingProcessAccountObjectId"
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