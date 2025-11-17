resource "azurerm_sentinel_alert_rule_scheduled" "potential_com_objects_download_cradles_usage_process_creation" {
  name                       = "potential_com_objects_download_cradles_usage_process_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential COM Objects Download Cradles Usage - Process Creation"
  description                = "Detects usage of COM objects that can be abused to download files in PowerShell by CLSID - Legitimate use of the library"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "[Type]::GetTypeFromCLSID(" and (ProcessCommandLine contains "0002DF01-0000-0000-C000-000000000046" or ProcessCommandLine contains "F6D90F16-9C73-11D3-B32E-00C04F990BB4" or ProcessCommandLine contains "F5078F35-C551-11D3-89B9-0000F81FE221" or ProcessCommandLine contains "88d96a0a-f192-11d4-a65f-0040963251e5" or ProcessCommandLine contains "AFBA6B42-5692-48EA-8141-DC517DCF0EF1" or ProcessCommandLine contains "AFB40FFD-B609-40A3-9828-F88BBE11E4E3" or ProcessCommandLine contains "88d96a0b-f192-11d4-a65f-0040963251e5" or ProcessCommandLine contains "2087c2f4-2cef-4953-a8ab-66779b670495" or ProcessCommandLine contains "000209FF-0000-0000-C000-000000000046" or ProcessCommandLine contains "00024500-0000-0000-C000-000000000046")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1105"]
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