resource "azurerm_sentinel_alert_rule_scheduled" "access_to_browser_credential_files_by_uncommon_applications" {
  name                       = "access_to_browser_credential_files_by_uncommon_applications"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Access To Browser Credential Files By Uncommon Applications"
  description                = "Detects file access requests to browser credential stores by uncommon processes. Could indicate potential attempt of credential stealing. Requires heavy baselining before usage - Antivirus, Anti-Spyware, Anti-Malware Software - Backup software - Legitimate software installed on partitions other than \"C:\\\" - Searching software such as \"everything.exe\""
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where ((FileName contains "\\User Data\\Default\\Login Data" or FileName contains "\\User Data\\Local State") or (FileName endswith "\\cookies.sqlite" or FileName endswith "\\places.sqlite" or FileName endswith "release\\key3.db" or FileName endswith "release\\key4.db" or FileName endswith "release\\logins.json") or FileName endswith "\\Appdata\\Local\\Microsoft\\Windows\\WebCache\\WebCacheV01.dat") and (not(((InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\system32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\") or InitiatingProcessFolderPath =~ "System"))) and (not((((InitiatingProcessFolderPath endswith "\\MpCopyAccelerator.exe" or InitiatingProcessFolderPath endswith "\\MsMpEng.exe") and InitiatingProcessFolderPath startswith "C:\\ProgramData\\Microsoft\\Windows Defender\\") or (InitiatingProcessFolderPath endswith "\\thor.exe" or InitiatingProcessFolderPath endswith "\\thor64.exe"))))
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