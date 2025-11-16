resource "azurerm_sentinel_alert_rule_scheduled" "windows_recall_feature_enabled_registry" {
  name                       = "windows_recall_feature_enabled_registry"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows Recall Feature Enabled - Registry"
  description                = "Detects the enabling of the Windows Recall feature via registry manipulation. Windows Recall can be enabled by setting the value of \"DisableAIDataAnalysis\" to \"0\". Adversaries may enable Windows Recall as part of post-exploitation discovery and collection activities. This rule assumes that Recall is already explicitly disabled on the host, and subsequently enabled by the adversary. - Legitimate use/activation of Windows Recall"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryValueData =~ "DWORD (0x00000000)" and RegistryKey endswith "\\Software\\Policies\\Microsoft\\Windows\\WindowsAI\\DisableAIDataAnalysis"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Collection"]
  techniques                 = ["T1113"]
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