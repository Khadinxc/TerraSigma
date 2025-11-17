resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_child_process_spawned_by_odbcconf_exe" {
  name                       = "uncommon_child_process_spawned_by_odbcconf_exe"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Child Process Spawned By Odbcconf.EXE"
  description                = "Detects an uncommon child process of \"odbcconf.exe\" binary which normally shouldn't have any child processes. - In rare occurrences where \"odbcconf\" crashes. It might spawn a \"werfault\" process - Other child processes will depend on the DLL being registered by actions like \"regsvr\". In case where the DLLs have external calls (which should be rare). Other child processes might spawn and additional filters need to be applied."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where InitiatingProcessFolderPath endswith "\\odbcconf.exe"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1218"]
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