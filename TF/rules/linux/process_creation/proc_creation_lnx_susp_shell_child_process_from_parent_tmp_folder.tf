resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_lnx_susp_shell_child_process_from_parent_tmp_folder" {
  name                       = "proc_creation_lnx_susp_shell_child_process_from_parent_tmp_folder"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Shell Execution Of Process Located In Tmp Directory"
  description                = <<DESC
    Detects execution of shells from a parent process located in a temporary (/tmp) directory

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_susp_shell_child_process_from_parent_tmp_folder.yml
  DESC
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (FolderPath endswith "/bash" or FolderPath endswith "/csh" or FolderPath endswith "/dash" or FolderPath endswith "/fish" or FolderPath endswith "/ksh" or FolderPath endswith "/sh" or FolderPath endswith "/zsh") and InitiatingProcessFolderPath startswith "/tmp/"
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
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