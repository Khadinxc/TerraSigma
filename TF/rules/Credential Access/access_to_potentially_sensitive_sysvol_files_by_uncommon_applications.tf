resource "azurerm_sentinel_alert_rule_scheduled" "access_to_potentially_sensitive_sysvol_files_by_uncommon_applications" {
  name                       = "access_to_potentially_sensitive_sysvol_files_by_uncommon_applications"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Access To Potentially Sensitive Sysvol Files By Uncommon Applications"
  description                = "Detects file access requests to potentially sensitive files hosted on the Windows Sysvol share."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where ((FileName contains "\\sysvol\\" and FileName contains "\\Policies\\") and (FileName endswith "audit.csv" or FileName endswith "Files.xml" or FileName endswith "GptTmpl.inf" or FileName endswith "groups.xml" or FileName endswith "Registry.pol" or FileName endswith "Registry.xml" or FileName endswith "scheduledtasks.xml" or FileName endswith "scripts.ini" or FileName endswith "services.xml") and FileName startswith "\\") and (not((InitiatingProcessFolderPath =~ "C:\\Windows\\explorer.exe" or (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\system32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CredentialAccess"]
  techniques                 = ["T1552"]
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