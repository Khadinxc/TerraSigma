resource "azurerm_sentinel_alert_rule_scheduled" "azure_ad_health_monitoring_agent_registry_keys_access" {
  name                       = "azure_ad_health_monitoring_agent_registry_keys_access"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Azure AD Health Monitoring Agent Registry Keys Access"
  description                = "This detection uses Windows security events to detect suspicious access attempts to the registry key of Azure AD Health monitoring agent. This detection requires an access control entry (ACE) on the system access control list (SACL) of the following securable object HKLM\\SOFTWARE\\Microsoft\\Microsoft Online\\Reporting\\MonitoringAgent."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey =~ "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Microsoft Online\\Reporting\\MonitoringAgent" and (not((InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.DiagnosticsAgent.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.InsightsService.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.MonitoringAgent.Startup.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Adfs.PshSurrogate.exe" or InitiatingProcessFolderPath contains "Microsoft.Identity.Health.Common.Clients.ResourceMonitor.exe")))
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}