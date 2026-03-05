resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_kerberos_coercion_via_dns_spn_spoofing" {
  name                       = "proc_creation_win_kerberos_coercion_via_dns_spn_spoofing"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Attempts of Kerberos Coercion Via DNS SPN Spoofing"
  description                = <<DESC
    Detects the presence of "UWhRC....AAYBAAAA" pattern in command line. The pattern "1UWhRCAAAAA..BAAAA" is a base64-encoded signature that corresponds to a marshaled CREDENTIAL_TARGET_INFORMATION structure. Attackers can use this technique to coerce authentication from victim systems to attacker-controlled hosts. It is one of the strong indicators of a Kerberos coercion attack, where adversaries manipulate DNS records to spoof Service Principal Names (SPNs) and redirect authentication requests like in CVE-2025-33073. If you see this pattern in the command line, it is likely an attempt to add spoofed Service Principal Names (SPNs) to DNS records, or checking for the presence of such records through the `nslookup` command.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_kerberos_coercion_via_dns_spn_spoofing.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ProcessCommandLine contains "UWhRCA" and ProcessCommandLine contains "BAAAA"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection", "CredentialAccess", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1557", "T1187"]
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