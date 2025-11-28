resource "azurerm_sentinel_alert_rule_scheduled" "wab_wabmig_unusual_parent_or_child_processes" {
  name                       = "wab_wabmig_unusual_parent_or_child_processes"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Wab/Wabmig Unusual Parent Or Child Processes"
  description                = "Detects unusual parent or children of the wab.exe (Windows Contacts) and Wabmig.exe (Microsoft Address Book Import Tool) processes as seen being used with bumblebee activity"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath endswith "\\wab.exe" or InitiatingProcessFolderPath endswith "\\wabmig.exe") or ((FolderPath endswith "\\wab.exe" or FolderPath endswith "\\wabmig.exe") and (InitiatingProcessFolderPath endswith "\\WmiPrvSE.exe" or InitiatingProcessFolderPath endswith "\\svchost.exe" or InitiatingProcessFolderPath endswith "\\dllhost.exe"))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "Execution"]
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