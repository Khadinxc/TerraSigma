resource "azurerm_sentinel_alert_rule_scheduled" "pua_ngrok_execution" {
  name                       = "pua_ngrok_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - Ngrok Execution"
  description                = "Detects the use of Ngrok, a utility used for port forwarding and tunneling, often used by threat actors to make local protected services publicly available. Involved domains are bin.equinox.io for download and *.ngrok.io for connections. - Another tool that uses the command line switches of Ngrok - Ngrok http 3978 (https://learn.microsoft.com/en-us/azure/bot-service/bot-service-debug-channel-ngrok?view=azure-bot-service-4.0)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains " tcp 139" or ProcessCommandLine contains " tcp 445" or ProcessCommandLine contains " tcp 3389" or ProcessCommandLine contains " tcp 5985" or ProcessCommandLine contains " tcp 5986") or (ProcessCommandLine contains " start " and ProcessCommandLine contains "--all" and ProcessCommandLine contains "--config" and ProcessCommandLine contains ".yml") or ((ProcessCommandLine contains " tcp " or ProcessCommandLine contains " http " or ProcessCommandLine contains " authtoken ") and FolderPath endswith "ngrok.exe") or (ProcessCommandLine contains ".exe authtoken " or ProcessCommandLine contains ".exe start --all")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1572"]
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