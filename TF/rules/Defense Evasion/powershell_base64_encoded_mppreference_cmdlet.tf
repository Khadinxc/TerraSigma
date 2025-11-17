resource "azurerm_sentinel_alert_rule_scheduled" "powershell_base64_encoded_mppreference_cmdlet" {
  name                       = "powershell_base64_encoded_mppreference_cmdlet"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Powershell Base64 Encoded MpPreference Cmdlet"
  description                = "Detects base64 encoded \"MpPreference\" PowerShell cmdlet code that tries to modifies or tamper with Windows Defender AV"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "QWRkLU1wUHJlZmVyZW5jZS" or ProcessCommandLine contains "FkZC1NcFByZWZlcmVuY2Ug" or ProcessCommandLine contains "BZGQtTXBQcmVmZXJlbmNlI" or ProcessCommandLine contains "U2V0LU1wUHJlZmVyZW5jZS" or ProcessCommandLine contains "NldC1NcFByZWZlcmVuY2Ug" or ProcessCommandLine contains "TZXQtTXBQcmVmZXJlbmNlI" or ProcessCommandLine contains "YWRkLW1wcHJlZmVyZW5jZS" or ProcessCommandLine contains "FkZC1tcHByZWZlcmVuY2Ug" or ProcessCommandLine contains "hZGQtbXBwcmVmZXJlbmNlI" or ProcessCommandLine contains "c2V0LW1wcHJlZmVyZW5jZS" or ProcessCommandLine contains "NldC1tcHByZWZlcmVuY2Ug" or ProcessCommandLine contains "zZXQtbXBwcmVmZXJlbmNlI") or (ProcessCommandLine contains "QQBkAGQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA" or ProcessCommandLine contains "EAZABkAC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA" or ProcessCommandLine contains "BAGQAZAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA" or ProcessCommandLine contains "UwBlAHQALQBNAHAAUAByAGUAZgBlAHIAZQBuAGMAZQAgA" or ProcessCommandLine contains "MAZQB0AC0ATQBwAFAAcgBlAGYAZQByAGUAbgBjAGUAIA" or ProcessCommandLine contains "TAGUAdAAtAE0AcABQAHIAZQBmAGUAcgBlAG4AYwBlACAA" or ProcessCommandLine contains "YQBkAGQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA" or ProcessCommandLine contains "EAZABkAC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA" or ProcessCommandLine contains "hAGQAZAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA" or ProcessCommandLine contains "cwBlAHQALQBtAHAAcAByAGUAZgBlAHIAZQBuAGMAZQAgA" or ProcessCommandLine contains "MAZQB0AC0AbQBwAHAAcgBlAGYAZQByAGUAbgBjAGUAIA" or ProcessCommandLine contains "zAGUAdAAtAG0AcABwAHIAZQBmAGUAcgBlAG4AYwBlACAA")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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