resource "azurerm_sentinel_alert_rule_scheduled" "outbound_rdp_connections_over_non_standard_tools" {
  name                       = "outbound_rdp_connections_over_non_standard_tools"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Outbound RDP Connections Over Non-Standard Tools"
  description                = "Detects Non-Standard tools initiating a connection over port 3389 indicating possible lateral movement. An initial baseline is required before using this utility to exclude third party RDP tooling that you might use. - Third party RDP tools"
  severity                   = "High"
  query                      = <<QUERY
DeviceNetworkEvents
| where RemotePort == 3389 and (not((InitiatingProcessFolderPath in~ ("C:\\Windows\\System32\\mstsc.exe", "C:\\Windows\\SysWOW64\\mstsc.exe")))) and (not(((InitiatingProcessFolderPath endswith "\\Avast Software\\Avast\\AvastSvc.exe" or InitiatingProcessFolderPath endswith "\\Avast\\AvastSvc.exe") or InitiatingProcessFolderPath =~ "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" or (InitiatingProcessFolderPath =~ "C:\\Windows\\System32\\dns.exe" and Protocol =~ "udp" and LocalPort == 53) or InitiatingProcessFolderPath =~ "" or InitiatingProcessFolderPath =~ "C:\\Program Files\\Mozilla Firefox\\firefox.exe" or isnull(InitiatingProcessFolderPath) or InitiatingProcessFolderPath endswith "\\Ranger\\SentinelRanger.exe" or InitiatingProcessFolderPath startswith "C:\\Program Files\\SplunkUniversalForwarder\\bin\\" or InitiatingProcessFolderPath endswith "\\RDCMan.exe" or (InitiatingProcessFolderPath endswith "\\FSAssessment.exe" or InitiatingProcessFolderPath endswith "\\FSDiscovery.exe" or InitiatingProcessFolderPath endswith "\\MobaRTE.exe" or InitiatingProcessFolderPath endswith "\\mRemote.exe" or InitiatingProcessFolderPath endswith "\\mRemoteNG.exe" or InitiatingProcessFolderPath endswith "\\Passwordstate.exe" or InitiatingProcessFolderPath endswith "\\RemoteDesktopManager.exe" or InitiatingProcessFolderPath endswith "\\RemoteDesktopManager64.exe" or InitiatingProcessFolderPath endswith "\\RemoteDesktopManagerFree.exe" or InitiatingProcessFolderPath endswith "\\RSSensor.exe" or InitiatingProcessFolderPath endswith "\\RTS2App.exe" or InitiatingProcessFolderPath endswith "\\RTSApp.exe" or InitiatingProcessFolderPath endswith "\\spiceworks-finder.exe" or InitiatingProcessFolderPath endswith "\\Terminals.exe" or InitiatingProcessFolderPath endswith "\\ws_TunnelService.exe") or (InitiatingProcessFolderPath endswith "\\thor.exe" or InitiatingProcessFolderPath endswith "\\thor64.exe") or (InitiatingProcessFolderPath in~ ("C:\\Program Files\\TSplus\\Java\\bin\\HTML5service.exe", "C:\\Program Files (x86)\\TSplus\\Java\\bin\\HTML5service.exe")) or InitiatingProcessFolderPath =~ "<unknown process>")))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["LateralMovement"]
  techniques                 = ["T1021"]
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