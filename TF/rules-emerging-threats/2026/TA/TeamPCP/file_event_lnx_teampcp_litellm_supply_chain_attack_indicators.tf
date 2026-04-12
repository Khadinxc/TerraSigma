resource "azurerm_sentinel_alert_rule_scheduled" "file_event_lnx_teampcp_litellm_supply_chain_attack_indicators" {
  name                       = "file_event_lnx_teampcp_litellm_supply_chain_attack_indicators"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "TeamPCP LiteLLM Supply Chain Attack Persistence Indicators"
  description                = <<DESC
    Detects the creation of specific persistence files as observed in the LiteLLM PyPI supply chain attack. In March 2026, a supply chain attack was discovered involving the popular open-source LLM framework LiteLLM by Threat Actor TeamPCP. The malicious package harvests every credential on the system, encrypts and exfiltrates them, and installs a persistent C2 backdoor.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules-emerging-threats/2026/TA/TeamPCP/file_event_lnx_teampcp_litellm_supply_chain_attack_indicators.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where InitiatingProcessFolderPath contains "/python3" and (FolderPath endswith "/.config/sysmon/sysmon.py" or FolderPath endswith "/.config/systemd/user/sysmon.service")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation", "InitialAccess"]
  techniques                 = ["T1543", "T1195"]
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