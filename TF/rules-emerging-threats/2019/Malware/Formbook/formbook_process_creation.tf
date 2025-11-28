resource "azurerm_sentinel_alert_rule_scheduled" "formbook_process_creation" {
  name                       = "formbook_process_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Formbook Process Creation"
  description                = "Detects Formbook like process executions that inject code into a set of files in the System32 folder, which executes a special command command line to delete the dropper from the AppData Temp folder. We avoid false positives by excluding all parent process with command line parameters."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessCommandLine endswith ".exe" and (InitiatingProcessCommandLine startswith "C:\\Windows\\System32\\" or InitiatingProcessCommandLine startswith "C:\\Windows\\SysWOW64\\")) and ((ProcessCommandLine contains "/c" and ProcessCommandLine contains "del" and ProcessCommandLine contains "C:\\Users\\" and ProcessCommandLine contains "\\AppData\\Local\\Temp\\") or (ProcessCommandLine contains "/c" and ProcessCommandLine contains "del" and ProcessCommandLine contains "C:\\Users\\" and ProcessCommandLine contains "\\Desktop\\") or (ProcessCommandLine contains "/C" and ProcessCommandLine contains "type nul >" and ProcessCommandLine contains "C:\\Users\\" and ProcessCommandLine contains "\\Desktop\\")) and ProcessCommandLine endswith ".exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["ResourceDevelopment"]
  techniques                 = ["T1587"]
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
}