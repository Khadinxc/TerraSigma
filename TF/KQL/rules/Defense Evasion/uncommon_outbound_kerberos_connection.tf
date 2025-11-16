resource "azurerm_sentinel_alert_rule_scheduled" "uncommon_outbound_kerberos_connection" {
  name                       = "uncommon_outbound_kerberos_connection"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Uncommon Outbound Kerberos Connection"
  description                = "Detects uncommon outbound network activity via Kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation. - Web Browsers and third party application might generate similar activity. An initial baseline is required."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemotePort == 88 and (not(InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\lsass.exe")) and (not(((InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe")) or (InitiatingProcessFolderPath in~ ("C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe", "C:\\Program Files\\Mozilla Firefox\\firefox.exe")) or InitiatingProcessFolderPath endswith "\\tomcat\\bin\\tomcat8.exe")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion", "CredentialAccess", "LateralMovement"]
  techniques                 = ["T1558", "T1550"]
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
      identifier  = "ProcessPath"
      column_name = "InitiatingProcessFolderPath"
    }
  }
}