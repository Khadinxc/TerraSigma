resource "azurerm_sentinel_alert_rule_scheduled" "registry_modification_attempt_via_vbscript" {
  name                       = "registry_modification_attempt_via_vbscript"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Registry Modification Attempt Via VBScript"
  description                = "Detects attempts to modify the registry using VBScript's CreateObject(\"Wscript.shell\") and RegWrite methods via common LOLBINs. It could be an attempt to modify the registry for persistence without using straightforward methods like regedit.exe, reg.exe, or PowerShell. Threat Actors may use this technique to evade detection by security solutions that monitor for direct registry modifications through traditional tools."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "CreateObject" and ProcessCommandLine contains "Wscript.shell" and ProcessCommandLine contains ".RegWrite"
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

  entity_mapping {
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}