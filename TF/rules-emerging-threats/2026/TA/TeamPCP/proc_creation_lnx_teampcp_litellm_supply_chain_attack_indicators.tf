resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_teampcp_litellm_supply_chain_attack_indicators" {
  name                       = "proc_creation_lnx_teampcp_litellm_supply_chain_attack_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "LiteLLM / TeamPCP Supply Chain Attack Indicators"
  description                = <<DESC
    Detects process executions related to the backdoored versions of LiteLLM (v1.82.7 or v1.82.8). In March 2026, a supply chain attack was discovered involving the popular open-source LLM framework LiteLLM by Threat Actor TeamPCP. The malicious package harvests every credential on the system, encrypts and exfiltrates them, and installs a persistent C2 backdoor.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2026/TA/TeamPCP/proc_creation_lnx_teampcp_litellm_supply_chain_attack_indicators.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "models.litellm.cloud" and ProcessCommandLine contains "X-Filename: tpcp.tar.gz") and FolderPath endswith "/curl") or ((ProcessCommandLine contains "exec(base64.b64decode('aW1wb3J0" and ProcessCommandLine contains "kI2NF9TQ1JJUFQgPSAiYV") and FolderPath contains "/python3") or ((ProcessCommandLine contains "systemctl" and ProcessCommandLine contains "--user" and ProcessCommandLine contains "sysmon") and InitiatingProcessFolderPath contains "/python3") or ((ProcessCommandLine contains "tpcp.tar.gz" and ProcessCommandLine contains "payload.enc" and ProcessCommandLine contains "session.key.enc") and FolderPath endswith "/tar")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["InitialAccess", "Collection", "Persistence", "PrivilegeEscalation"]
  techniques                 = ["T1195", "T1560", "T1543"]
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

  entity_mapping {
    entity_type = "File"
    field_mapping {
      identifier  = "Name"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}