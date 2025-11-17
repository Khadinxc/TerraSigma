resource "azurerm_sentinel_alert_rule_scheduled" "powershell_base64_encoded_frombase64string_cmdlet" {
  name                       = "powershell_base64_encoded_frombase64string_cmdlet"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PowerShell Base64 Encoded FromBase64String Cmdlet"
  description                = "Detects usage of a base64 encoded \"FromBase64String\" cmdlet in a process command line"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "OjpGcm9tQmFzZTY0U3RyaW5n" or ProcessCommandLine contains "o6RnJvbUJhc2U2NFN0cmluZ" or ProcessCommandLine contains "6OkZyb21CYXNlNjRTdHJpbm" or (ProcessCommandLine contains "OgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcA" or ProcessCommandLine contains "oAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnA" or ProcessCommandLine contains "6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZw")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1140", "T1059"]
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