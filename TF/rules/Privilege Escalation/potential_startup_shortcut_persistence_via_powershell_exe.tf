resource "azurerm_sentinel_alert_rule_scheduled" "potential_startup_shortcut_persistence_via_powershell_exe" {
  name                       = "potential_startup_shortcut_persistence_via_powershell_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Startup Shortcut Persistence Via PowerShell.EXE"
  description                = "Detects PowerShell writing startup shortcuts. This procedure was highlighted in Red Canary Intel Insights Oct. 2021, \"We frequently observe adversaries using PowerShell to write malicious .lnk files into the startup directory to establish persistence. Accordingly, this detection opportunity is likely to identify persistence mechanisms in multiple threats. In the context of Yellow Cockatoo, this persistence mechanism eventually launches the command-line script that leads to the installation of a malicious DLL\" - Depending on your environment accepted applications may leverage this at times. It is recommended to search for anomalies inidicative of malware."
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where (InitiatingProcessFolderPath endswith "\\powershell.exe" or InitiatingProcessFolderPath endswith "\\pwsh.exe") and FolderPath contains "\\start menu\\programs\\startup\\" and FolderPath endswith ".lnk"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1547"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}