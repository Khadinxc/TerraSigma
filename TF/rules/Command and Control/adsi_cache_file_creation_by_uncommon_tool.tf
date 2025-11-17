resource "azurerm_sentinel_alert_rule_scheduled" "adsi_cache_file_creation_by_uncommon_tool" {
  name                       = "adsi_cache_file_creation_by_uncommon_tool"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "ADSI-Cache File Creation By Uncommon Tool"
  description                = "Detects the creation of an \"Active Directory Schema Cache File\" (.sch) file by an uncommon tool. - Other legimate tools, which do ADSI (LDAP) operations, e.g. any remoting activity by MMC, Powershell, Windows etc."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceFileEvents
| where (FolderPath contains "\\Local\\Microsoft\\Windows\\SchCache\\" and FolderPath endswith ".sch") and (not((((InitiatingProcessFolderPath endswith ":\\Program Files\\Cylance\\Desktop\\CylanceSvc.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\CCM\\CcmExec.exe" or InitiatingProcessFolderPath endswith ":\\windows\\system32\\dllhost.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\system32\\dsac.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\system32\\efsui.exe" or InitiatingProcessFolderPath endswith ":\\windows\\system32\\mmc.exe" or InitiatingProcessFolderPath endswith ":\\windows\\system32\\svchost.exe" or InitiatingProcessFolderPath endswith ":\\Windows\\System32\\wbem\\WmiPrvSE.exe" or InitiatingProcessFolderPath endswith ":\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe") or (InitiatingProcessFolderPath contains ":\\Windows\\ccmsetup\\autoupgrade\\ccmsetup" or InitiatingProcessFolderPath contains ":\\Program Files\\SentinelOne\\Sentinel Agent")) or ((InitiatingProcessFolderPath contains ":\\Program Files\\" and InitiatingProcessFolderPath contains "\\Microsoft Office") and InitiatingProcessFolderPath endswith "\\OUTLOOK.EXE")))) and (not((InitiatingProcessFolderPath endswith ":\\Program Files\\Citrix\\Receiver StoreFront\\Services\\DefaultDomainServices\\Citrix.DeliveryServices.DomainServices.ServiceHost.exe" or InitiatingProcessFolderPath endswith "\\LANDesk\\LDCLient\\ldapwhoami.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["CommandAndControl"]
  techniques                 = ["T1001"]
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