resource "azurerm_sentinel_alert_rule_scheduled" "clickonce_trust_prompt_tampering" {
  name                       = "clickonce_trust_prompt_tampering"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ClickOnce Trust Prompt Tampering"
  description                = "Detects changes to the ClickOnce trust prompt registry key in order to enable an installation from different locations such as the Internet. - Legitimate internal requirements."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "Enabled" and RegistryKey endswith "\\SOFTWARE\\MICROSOFT\\.NETFramework\\Security\\TrustManager\\PromptingLevel*" and (RegistryKey endswith "\\Internet" or RegistryKey endswith "\\LocalIntranet" or RegistryKey endswith "\\MyComputer" or RegistryKey endswith "\\TrustedSites" or RegistryKey endswith "\\UntrustedSites")
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
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
    field_mapping {
      identifier  = "ValueData"
      column_name = "RegistryValueData"
    }
  }
}