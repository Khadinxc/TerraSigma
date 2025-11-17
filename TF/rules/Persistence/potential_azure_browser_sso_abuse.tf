resource "azurerm_sentinel_alert_rule_scheduled" "potential_azure_browser_sso_abuse" {
  name                       = "potential_azure_browser_sso_abuse"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Azure Browser SSO Abuse"
  description                = "Detects abusing Azure Browser SSO by requesting OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user."
  severity                   = "Low"
  query                      = <<QUERY
DeviceImageLoadEvents
| where FolderPath =~ "C:\\Windows\\System32\\MicrosoftAccountTokenProvider.dll" and (not((InitiatingProcessFolderPath endswith "\\BackgroundTaskHost.exe" and (InitiatingProcessFolderPath startswith "C:\\Windows\\System32\\" or InitiatingProcessFolderPath startswith "C:\\Windows\\SysWOW64\\")))) and (not(((InitiatingProcessFolderPath endswith "\\IDE\\devenv.exe" and (InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft Visual Studio\\" or InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft Visual Studio\\")) or (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application\\" or InitiatingProcessFolderPath endswith "\\WindowsApps\\MicrosoftEdge.exe" or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))) or ((InitiatingProcessFolderPath endswith "\\msedge.exe" or InitiatingProcessFolderPath endswith "\\msedgewebview2.exe") and (InitiatingProcessFolderPath startswith "C:\\Program Files (x86)\\Microsoft\\EdgeCore\\" or InitiatingProcessFolderPath startswith "C:\\Program Files\\Microsoft\\EdgeCore\\")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe", "C:\\Program Files\\Internet Explorer\\iexplore.exe")) or isnull(InitiatingProcessFolderPath) or InitiatingProcessFolderPath endswith "\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Persistence", "DefenseEvasion", "PrivilegeEscalation"]
  techniques                 = ["T1574"]
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