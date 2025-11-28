resource "azurerm_sentinel_alert_rule_scheduled" "registry_tampering_by_potentially_suspicious_processes" {
  name                       = "registry_tampering_by_potentially_suspicious_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Tampering by Potentially Suspicious Processes"
  description                = "Detects suspicious registry modifications made by suspicious processes such as script engine processes such as WScript, or CScript etc. These processes are rarely used for legitimate registry modifications, and their activity may indicate an attempt to modify the registry without using standard tools like regedit.exe or reg.exe, potentially for evasion and persistence. - Some legitimate admin or install scripts may use these processes for registry modifications."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Persistence", "Execution"]
  techniques                 = ["T1112", "T1059"]
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
}