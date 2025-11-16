resource "azurerm_sentinel_alert_rule_scheduled" "ntds_dit_creation_by_uncommon_parent_process" {
  name                       = "ntds_dit_creation_by_uncommon_parent_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "NTDS.DIT Creation By Uncommon Parent Process"
  description                = "Detects creation of a file named \"ntds.dit\" (Active Directory Database) by an uncommon parent process or directory"
  severity                   = "High"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith "\\ntds.dit" and ((InitiatingProcessParentFileName in~ ("cscript.exe", "httpd.exe", "nginx.exe", "php-cgi.exe", "powershell.exe", "pwsh.exe", "w3wp.exe", "wscript.exe")) or (InitiatingProcessParentFileName startswith "apache" or InitiatingProcessParentFileName startswith "tomcat" or InitiatingProcessParentFileName startswith "" or InitiatingProcessParentFileName startswith "" or InitiatingProcessParentFileName startswith "" or InitiatingProcessParentFileName startswith ""))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1003"]
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
      identifier  = "ProcessName"
      column_name = "FileName"
    }
    field_mapping {
      identifier  = "ProcessPath"
      column_name = "FolderPath"
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