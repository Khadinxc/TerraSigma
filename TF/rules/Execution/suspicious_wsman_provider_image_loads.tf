resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_wsman_provider_image_loads" {
  name                       = "suspicious_wsman_provider_image_loads"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious WSMAN Provider Image Loads"
  description                = "Detects signs of potential use of the WSMAN provider from uncommon processes locally and remote execution."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceImageLoadEvents
| where (((FolderPath endswith "\\WsmSvc.dll" or FolderPath endswith "\\WsmAuto.dll" or FolderPath endswith "\\Microsoft.WSMan.Management.ni.dll") or (InitiatingProcessVersionInfoOriginalFileName in~ ("WsmSvc.dll", "WSMANAUTOMATION.DLL", "Microsoft.WSMan.Management.dll"))) or (InitiatingProcessFolderPath endswith "\\svchost.exe" and InitiatingProcessVersionInfoOriginalFileName =~ "WsmWmiPl.dll")) and (not((InitiatingProcessFolderPath startswith "C:\\Program Files\\Citrix\\" or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\PowerShell\\6\\pwsh.exe", "C:\\Program Files (x86)\\PowerShell\\7\\pwsh.exe", "C:\\Program Files\\PowerShell\\6\\pwsh.exe", "C:\\Program Files\\PowerShell\\7\\pwsh.exe", "C:\\Windows\\System32\\sdiagnhost.exe", "C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell_ise.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")) or InitiatingProcessFolderPath endswith "\\mmc.exe" or (InitiatingProcessFolderPath endswith "\\mscorsvw.exe" and (InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\Framework64\\v" or InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\Framework\\v" or InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\FrameworkArm\\v" or InitiatingProcessFolderPath startswith "C:\\Windows\\Microsoft.NET\\FrameworkArm64\\v")) or InitiatingProcessFolderPath startswith "C:\\Windows\\Temp\\asgard2-agent\\" or (InitiatingProcessCommandLine contains "svchost.exe -k netsvcs -p -s BITS" or InitiatingProcessCommandLine contains "svchost.exe -k GraphicsPerfSvcGroup -s GraphicsPerfSvc" or InitiatingProcessCommandLine contains "svchost.exe -k NetworkService -p -s Wecsvc" or InitiatingProcessCommandLine contains "svchost.exe -k netsvcs") or (InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\Configure-SMRemoting.exe", "C:\\Windows\\System32\\ServerManager.exe")) or InitiatingProcessFolderPath startswith "C:\\$WINDOWS.~BT\\Sources\\"))) and (not((InitiatingProcessFolderPath endswith "\\svchost.exe" and isnull(InitiatingProcessCommandLine))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution", "LateralMovement"]
  techniques                 = ["T1059", "T1021"]
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
    entity_type = "Process"
    field_mapping {
      identifier  = "CommandLine"
      column_name = "InitiatingProcessCommandLine"
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