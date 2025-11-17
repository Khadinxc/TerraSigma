resource "azurerm_sentinel_alert_rule_scheduled" "com_hijacking_via_treatas" {
  name                       = "com_hijacking_via_treatas"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "COM Hijacking via TreatAs"
  description                = "Detect modification of TreatAs key to enable \"rundll32.exe -sta\" command - Legitimate use"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where RegistryKey endswith "TreatAs\\(Default)" and (not(((InitiatingProcessFolderPath in~ ("C:\\Windows\\system32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe")) or (InitiatingProcessFolderPath endswith "\\OfficeClickToRun.exe" and InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\") or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\Microsoft Office\\root\\integration\\integrator.exe", "C:\\Program Files (x86)\\Microsoft Office\\root\\integration\\integrator.exe")) or InitiatingProcessFolderPath =~ "C:\\Windows\\system32\\svchost.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Persistence"]
  techniques                 = ["T1546"]
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