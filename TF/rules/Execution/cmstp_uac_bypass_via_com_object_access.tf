resource "azurerm_sentinel_alert_rule_scheduled" "cmstp_uac_bypass_via_com_object_access" {
  name                       = "cmstp_uac_bypass_via_com_object_access"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "CMSTP UAC Bypass via COM Object Access"
  description                = "Detects UAC Bypass Attempt Using Microsoft Connection Manager Profile Installer Autoelevate-capable COM Objects (e.g. UACMe ID of 41, 43, 58 or 65) - Legitimate CMSTP use (unlikely in modern enterprise environments)"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessIntegrityLevel in~ ("High", "System", "S-1-16-16384", "S-1-16-12288")) and (InitiatingProcessCommandLine contains " /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" or InitiatingProcessCommandLine contains " /Processid:{3E000D72-A845-4CD9-BD83-80C07C3B881F}" or InitiatingProcessCommandLine contains " /Processid:{BD54C901-076B-434E-B6C7-17C531F4AB41}" or InitiatingProcessCommandLine contains " /Processid:{D2E7041B-2927-42FB-8E9F-7CE93B6DC937}" or InitiatingProcessCommandLine contains " /Processid:{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}") and InitiatingProcessFolderPath endswith "\\DllHost.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1548", "T1218"]
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
      identifier  = "ProcessId"
      column_name = "ProcessId"
    }
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