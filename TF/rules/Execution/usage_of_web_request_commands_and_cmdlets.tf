resource "azurerm_sentinel_alert_rule_scheduled" "usage_of_web_request_commands_and_cmdlets" {
  name                       = "usage_of_web_request_commands_and_cmdlets"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Usage Of Web Request Commands And Cmdlets"
  description                = "Detects the use of various web request commands with commandline tools and Windows PowerShell cmdlets (including aliases) via CommandLine - Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "[System.Net.WebRequest]::create" or ProcessCommandLine contains "curl " or ProcessCommandLine contains "Invoke-RestMethod" or ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains " irm " or ProcessCommandLine contains "iwr " or ProcessCommandLine contains "Resume-BitsTransfer" or ProcessCommandLine contains "Start-BitsTransfer" or ProcessCommandLine contains "wget " or ProcessCommandLine contains "WinHttp.WinHttpRequest"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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