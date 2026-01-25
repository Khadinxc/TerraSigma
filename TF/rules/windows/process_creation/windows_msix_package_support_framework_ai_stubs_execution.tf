resource "azurerm_sentinel_alert_rule_scheduled" "windows_msix_package_support_framework_ai_stubs_execution" {
  name                       = "windows_msix_package_support_framework_ai_stubs_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Windows MSIX Package Support Framework AI_STUBS Execution"
  description                = "Detects execution of Advanced Installer MSIX Package Support Framework (PSF) components, specifically AI_STUBS executables with original filename 'popupwrapper.exe'. This activity may indicate malicious MSIX packages build with Advanced Installer leveraging the Package Support Framework to bypass application control restrictions. - Legitimate applications packaged with Advanced Installer using Package Support Framework"
  severity                   = "Low"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "\\AI_STUBS\\AiStubX64Elevated.exe" or FolderPath endswith "\\AI_STUBS\\AiStubX86Elevated.exe" or FolderPath endswith "\\AI_STUBS\\AiStubX64.exe" or FolderPath endswith "\\AI_STUBS\\AiStubX86.exe") and ProcessVersionInfoOriginalFileName =~ "popupwrapper.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
  techniques                 = ["T1218", "T1553", "T1204"]
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