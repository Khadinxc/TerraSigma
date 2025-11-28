resource "azurerm_sentinel_alert_rule_scheduled" "suspicious_powershell_parent_process" {
  name                       = "suspicious_powershell_parent_process"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Suspicious PowerShell Parent Process"
  description                = "Detects a suspicious or uncommon parent processes of PowerShell - Other scripts"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where (InitiatingProcessFolderPath contains "tomcat" or (InitiatingProcessFolderPath endswith "\\amigo.exe" or InitiatingProcessFolderPath endswith "\\browser.exe" or InitiatingProcessFolderPath endswith "\\chrome.exe" or InitiatingProcessFolderPath endswith "\\firefox.exe" or InitiatingProcessFolderPath endswith "\\httpd.exe" or InitiatingProcessFolderPath endswith "\\iexplore.exe" or InitiatingProcessFolderPath endswith "\\jbosssvc.exe" or InitiatingProcessFolderPath endswith "\\microsoftedge.exe" or InitiatingProcessFolderPath endswith "\\microsoftedgecp.exe" or InitiatingProcessFolderPath endswith "\\MicrosoftEdgeSH.exe" or InitiatingProcessFolderPath endswith "\\mshta.exe" or InitiatingProcessFolderPath endswith "\\nginx.exe" or InitiatingProcessFolderPath endswith "\\outlook.exe" or InitiatingProcessFolderPath endswith "\\php-cgi.exe" or InitiatingProcessFolderPath endswith "\\regsvr32.exe" or InitiatingProcessFolderPath endswith "\\rundll32.exe" or InitiatingProcessFolderPath endswith "\\safari.exe" or InitiatingProcessFolderPath endswith "\\services.exe" or InitiatingProcessFolderPath endswith "\\sqlagent.exe" or InitiatingProcessFolderPath endswith "\\sqlserver.exe" or InitiatingProcessFolderPath endswith "\\sqlservr.exe" or InitiatingProcessFolderPath endswith "\\vivaldi.exe" or InitiatingProcessFolderPath endswith "\\w3wp.exe")) and ((FolderPath endswith "\\powershell.exe" or FolderPath endswith "\\pwsh.exe") or (ProcessCommandLine contains "/c powershell" or ProcessCommandLine contains "/c pwsh") or ProcessVersionInfoFileDescription =~ "Windows PowerShell" or ProcessVersionInfoProductName =~ "PowerShell Core 6" or (ProcessVersionInfoOriginalFileName in~ ("PowerShell.EXE", "pwsh.dll")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Execution"]
  techniques                 = ["T1059"]
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
      column_name = "ProcessCommandLine"
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