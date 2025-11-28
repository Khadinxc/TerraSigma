resource "azurerm_sentinel_alert_rule_scheduled" "potential_muddywater_apt_activity" {
  name                       = "potential_muddywater_apt_activity"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential MuddyWater APT Activity"
  description                = "Detects potential Muddywater APT activity - Unlikely"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "vbscript:Close(Execute(\"CreateObject(" and ProcessCommandLine contains "powershell" and ProcessCommandLine contains "-w 1 -exec Bypass" and ProcessCommandLine contains "\\ProgramData\\") or (ProcessCommandLine contains "[Convert]::ToBase64String" and ProcessCommandLine contains "[System.Text.Encoding]::UTF8.GetString]" and ProcessCommandLine contains "GetResponse().GetResponseStream()" and ProcessCommandLine contains "[System.Net.HttpWebRequest]::Create(" and ProcessCommandLine contains "-bxor ") or (ProcessCommandLine contains "Win32_OperatingSystem" and ProcessCommandLine contains "Win32_NetworkAdapterConfiguration" and ProcessCommandLine contains "root\\SecurityCenter2" and ProcessCommandLine contains "[System.Net.DNS]")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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