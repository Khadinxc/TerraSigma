resource "azurerm_sentinel_alert_rule_scheduled" "azure_ad_health_service_agents_registry_keys_access" {
  name                       = "azure_ad_health_service_agents_registry_keys_access"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Azure AD Health Service Agents Registry Keys Access"
  description                = "This detection uses Windows security events to detect suspicious access attempts to the registry key values and sub-keys of Azure AD Health service agents (e.g AD FS). Information from AD Health service agents can be used to potentially abuse some of the features provided by those services in the cloud (e.g. Federation). This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object: HKLM:\\SOFTWARE\\Microsoft\\ADHealthAgent. Make sure you set the SACL to propagate to its sub-keys."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey =~ "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\ADHealthAgent" and (not((InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.InsightsService.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.PshSurrogate.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery"]
  techniques                 = ["T1012"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }

  entity_mapping {
    entity_type = "Registry"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}