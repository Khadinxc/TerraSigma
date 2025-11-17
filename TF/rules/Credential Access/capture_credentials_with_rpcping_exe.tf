resource "azurerm_sentinel_alert_rule_scheduled" "capture_credentials_with_rpcping_exe" {
  name                       = "capture_credentials_with_rpcping_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Capture Credentials with Rpcping.exe"
  description                = "Detects using Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process. - Unlikely"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "-s" or ProcessCommandLine contains "/s" or ProcessCommandLine contains "–s" or ProcessCommandLine contains "—s" or ProcessCommandLine contains "―s") and (FolderPath endswith "\\RpcPing.exe" or ProcessVersionInfoOriginalFileName =~ "\\RpcPing.exe")) and ((ProcessCommandLine contains "ncacn_np" and (ProcessCommandLine contains "-t" or ProcessCommandLine contains "/t" or ProcessCommandLine contains "–t" or ProcessCommandLine contains "—t" or ProcessCommandLine contains "―t")) or (ProcessCommandLine contains "NTLM" and (ProcessCommandLine contains "-u" or ProcessCommandLine contains "/u" or ProcessCommandLine contains "–u" or ProcessCommandLine contains "—u" or ProcessCommandLine contains "―u")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}