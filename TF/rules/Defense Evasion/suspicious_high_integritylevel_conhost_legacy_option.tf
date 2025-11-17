resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_high_integritylevel_conhost_legacy_option" {
  name                       = "suspicious_high_integritylevel_conhost_legacy_option"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious High IntegrityLevel Conhost Legacy Option"
  description                = "ForceV1 asks for information directly from the kernel space. Conhost connects to the console application. High IntegrityLevel means the process is running with elevated privileges, such as an Administrator context. - Very Likely, including launching cmd.exe via Run As Administrator"
  severity                   = "Informational"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "conhost.exe" and ProcessCommandLine contains "0xffffffff" and ProcessCommandLine contains "-ForceV1") and (ProcessIntegrityLevel in~ ("High", "S-1-16-12288"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1202"]
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