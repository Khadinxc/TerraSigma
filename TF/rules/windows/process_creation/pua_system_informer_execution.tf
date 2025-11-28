resource "azurerm_sentinel_alert_rule_scheduled" "pua_system_informer_execution" {
  name                       = "pua_system_informer_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - System Informer Execution"
  description                = "Detects the execution of System Informer, a task manager tool to view and manipulate processes, kernel options and other low level operations - System Informer is regularly used legitimately by system administrators or developers. Apply additional filters accordingly"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\SystemInformer.exe" or ProcessVersionInfoOriginalFileName =~ "SystemInformer.exe" or ProcessVersionInfoFileDescription =~ "System Informer" or ProcessVersionInfoProductName =~ "System Informer" or (MD5 startswith "19426363A37C03C3ED6FEDF57B6696EC" or SHA1 startswith "8B12C6DA8FAC0D5E8AB999C31E5EA04AF32D53DC" or SHA256 startswith "8EE9D84DE50803545937A63C686822388A3338497CDDB660D5D69CF68B68F287")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "PrivilegeEscalation", "Discovery", "DefenseEvasion"]
  techniques                 = ["T1082", "T1564", "T1543"]
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