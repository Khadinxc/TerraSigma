resource "azurerm_sentinel_alert_rule_scheduled" "image_load_dll_pcre_dotnet_dll_load" {
  name                       = "image_load_dll_pcre_dotnet_dll_load"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PCRE.NET Package Image Load"
  description                = "Detects processes loading modules related to PCRE.NET package Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_dll_pcre_dotnet_dll_load.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/image_load/image_load_dll_pcre_dotnet_dll_load.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath contains "\\AppData\\Local\\Temp\\ba9ea7344a4a5f591d6e5dc32a13494b\\"
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