resource "azurerm_sentinel_alert_rule_scheduled" "dotnet_clr_dll_loaded_by_scripting_applications" {
  name                       = "dotnet_clr_dll_loaded_by_scripting_applications"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "DotNet CLR DLL Loaded By Scripting Applications"
  description                = "Detects .NET CLR DLLs being loaded by scripting applications such as wscript or cscript. This could be an indication of potential suspicious execution."
  severity                   = "High"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (FolderPath endswith "\\clr.dll" or FolderPath endswith "\\mscoree.dll" or FolderPath endswith "\\mscorlib.dll") and (InitiatingProcessFolderPath endswith "\\cmstp.exe" or InitiatingProcessFolderPath endswith "\\cscript.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\msxsl.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\wmic.exe" or InitiatingProcessFolderPath endswith "\\wscript.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution", "PrivilegeEscalation"]
  techniques                 = ["T1055"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}