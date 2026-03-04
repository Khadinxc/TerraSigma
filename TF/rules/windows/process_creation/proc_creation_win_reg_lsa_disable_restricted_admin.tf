resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_reg_lsa_disable_restricted_admin" {
  name                       = "proc_creation_win_reg_lsa_disable_restricted_admin"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "RestrictedAdminMode Registry Value Tampering - ProcCreation"
  description                = "Detects changes to the \"DisableRestrictedAdmin\" registry value in order to disable or enable RestrictedAdmin mode. RestrictedAdmin mode prevents the transmission of reusable credentials to the remote system to which you connect using Remote Desktop. This prevents your credentials from being harvested during the initial connection process if the remote server has been compromise Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reg_lsa_disable_restricted_admin.yml | Source: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reg_lsa_disable_restricted_admin.yml"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "\\System\\CurrentControlSet\\Control\\Lsa" and ProcessCommandLine contains "DisableRestrictedAdmin"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion"]
  techniques                 = ["T1112"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "ProcessCommandLine"
    }
  }
}