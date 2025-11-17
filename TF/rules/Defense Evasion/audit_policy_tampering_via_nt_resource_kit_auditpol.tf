resource "azurerm_sentinel_alert_rule_scheduled" "audit_policy_tampering_via_nt_resource_kit_auditpol" {
  name                       = "audit_policy_tampering_via_nt_resource_kit_auditpol"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Audit Policy Tampering Via NT Resource Kit Auditpol"
  description                = "Threat actors can use an older version of the auditpol binary available inside the NT resource kit to change audit policy configuration to impair detection capability. This can be carried out by selectively disabling/removing certain audit policies as well as restoring a custom policy owned by the threat actor. - The old auditpol utility isn't available by default on recent versions of Windows as it was replaced by a newer version. The FP rate should be very low except for tools that use a similar flag structure"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "/logon:none" or ProcessCommandLine contains "/system:none" or ProcessCommandLine contains "/sam:none" or ProcessCommandLine contains "/privilege:none" or ProcessCommandLine contains "/object:none" or ProcessCommandLine contains "/process:none" or ProcessCommandLine contains "/policy:none"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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