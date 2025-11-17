resource "azurerm_sentinel_alert_rule_scheduled" "script_event_consumer_spawning_process" {
  name                       = "script_event_consumer_spawning_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Script Event Consumer Spawning Process"
  description                = "Detects a suspicious child process of Script Event Consumer (scrcons.exe)."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\svchost.exe" or FolderPath endswith "\\dllhost.exe" or FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe" or FolderPath endswith "\\wscript.exe" or FolderPath endswith "\\cscript.exe" or FolderPath endswith "\\schtasks.exe" or FolderPath endswith "\\regsvr32.exe" or FolderPath endswith "\\mshta.exe" or FolderPath endswith "\\rundll32.exe" or FolderPath endswith "\\msiexec.exe" or FolderPath endswith "\\msbuild.exe") and InitiatingProcessFolderPath endswith "\\scrcons.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1047"]
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