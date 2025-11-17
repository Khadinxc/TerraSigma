resource "azurerm_sentinel_alert_rule_scheduled" "commvault_qlogin_argument_injection_authentication_bypass_cve_2025_57791" {
  name                       = "commvault_qlogin_argument_injection_authentication_bypass_cve_2025_57791"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Commvault QLogin Argument Injection Authentication Bypass (CVE-2025-57791)"
  description                = "Detects the use of argument injection in the Commvault qlogin command - potential exploitation for CVE-2025-57791. An attacker can inject the `-localadmin` parameter via the password field to bypass authentication and gain a privileged token."
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "qlogin" and ProcessCommandLine contains " -cs " and ProcessCommandLine contains " -localadmin" and ProcessCommandLine contains " -clp " and ProcessCommandLine contains "_localadmin__"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess"]
  techniques                 = ["T1190"]
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