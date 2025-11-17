resource "azurerm_sentinel_alert_rule_scheduled" "potential_persistence_via_visual_studio_tools_for_office" {
  name                       = "potential_persistence_via_visual_studio_tools_for_office"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Persistence Via Visual Studio Tools for Office"
  description                = "Detects persistence via Visual Studio Tools for Office (VSTO) add-ins in Office applications. - Legitimate Addin Installation"
  severity                   = "Medium"
  query                      = <<QUERY
DeviceRegistryEvents
| where (RegistryKey endswith "\\Software\\Microsoft\\Office\\Outlook\\Addins*" or RegistryKey endswith "\\Software\\Microsoft\\Office\\Word\\Addins*" or RegistryKey endswith "\\Software\\Microsoft\\Office\\Excel\\Addins*" or RegistryKey endswith "\\Software\\Microsoft\\Office\\Powerpoint\\Addins*" or RegistryKey endswith "\\Software\\Microsoft\\VSTO\\Security\\Inclusion*") and (not(((InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Microsoft Office\\root\\integration\\integrator.exe", "C:\\Program Files\\Microsoft Office\\root\\integration\\integrator.exe")) or ((InitiatingProcessFolderPath endswith "\\excel.exe" or InitiatingProcessFolderPath endswith "\\Integrator.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\powerpnt.exe" or InitiatingProcessFolderPath endswith "\\Teams.exe" or InitiatingProcessFolderPath endswith "\\visio.exe" or InitiatingProcessFolderPath endswith "\\winword.exe") and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft Office\\OFFICE" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft Office\\OFFICE" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft Office\\Root\\OFFICE" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft Office\\Root\\OFFICE")) or (InitiatingProcessFolderPath endswith "\\OfficeClickToRun.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files (x86)\\Microsoft Shared\\ClickToRun\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Common Files\\Microsoft Shared\\ClickToRun\\")) or (InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\SysWOW64\\msiexec.exe", "C:\\Windows\\System32\\regsvr32.exe", "C:\\Windows\\SysWOW64\\regsvr32.exe"))))) and (not((((InitiatingProcessFolderPath in~ ("C:\\Program Files\\Avast Software\\Avast\\RegSvr.exe", "C:\\Program Files (x86)\\Avast Software\\Avast\\RegSvr.exe")) and RegistryKey endswith "\\Microsoft\\Office\\Outlook\\Addins\\Avast.AsOutExt*") or ((InitiatingProcessFolderPath in~ ("C:\\Program Files\\AVG\\Antivirus\\RegSvr.exe", "C:\\Program Files (x86)\\AVG\\Antivirus\\RegSvr.exe")) and RegistryKey endswith "\\Microsoft\\Office\\Outlook\\Addins\\Antivirus.AsOutExt*"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence"]
  techniques                 = ["T1137"]
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
    entity_type = "RegistryKey"
    field_mapping {
      identifier  = "Key"
      column_name = "RegistryKey"
    }
  }
}