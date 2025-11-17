resource "azurerm_sentinel_alert_rule_scheduled" "potential_tampering_with_security_products_via_wmic" {
  name                       = "potential_tampering_with_security_products_via_wmic"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "Potential Tampering With Security Products Via WMIC"
  description                = "Detects uninstallation or termination of security products using the WMIC utility - Legitimate administration"
  severity                   = "High"
  query                      = <<QUERY
DeviceProcessEvents
| where ((ProcessCommandLine contains "wmic" and ProcessCommandLine contains "product where " and ProcessCommandLine contains "call" and ProcessCommandLine contains "uninstall" and ProcessCommandLine contains "/nointeractive") or ((ProcessCommandLine contains "call delete" or ProcessCommandLine contains "call terminate") and (ProcessCommandLine contains "wmic" and ProcessCommandLine contains "caption like ")) or (ProcessCommandLine contains "process " and ProcessCommandLine contains "where " and ProcessCommandLine contains "delete")) and (ProcessCommandLine contains "%carbon%" or ProcessCommandLine contains "%cylance%" or ProcessCommandLine contains "%endpoint%" or ProcessCommandLine contains "%eset%" or ProcessCommandLine contains "%malware%" or ProcessCommandLine contains "%Sophos%" or ProcessCommandLine contains "%symantec%" or ProcessCommandLine contains "Antivirus" or ProcessCommandLine contains "AVG " or ProcessCommandLine contains "Carbon Black" or ProcessCommandLine contains "CarbonBlack" or ProcessCommandLine contains "Cb Defense Sensor 64-bit" or ProcessCommandLine contains "Crowdstrike Sensor" or ProcessCommandLine contains "Cylance " or ProcessCommandLine contains "Dell Threat Defense" or ProcessCommandLine contains "DLP Endpoint" or ProcessCommandLine contains "Endpoint Detection" or ProcessCommandLine contains "Endpoint Protection" or ProcessCommandLine contains "Endpoint Security" or ProcessCommandLine contains "Endpoint Sensor" or ProcessCommandLine contains "ESET File Security" or ProcessCommandLine contains "LogRhythm System Monitor Service" or ProcessCommandLine contains "Malwarebytes" or ProcessCommandLine contains "McAfee Agent" or ProcessCommandLine contains "Microsoft Security Client" or ProcessCommandLine contains "Sophos Anti-Virus" or ProcessCommandLine contains "Sophos AutoUpdate" or ProcessCommandLine contains "Sophos Credential Store" or ProcessCommandLine contains "Sophos Management Console" or ProcessCommandLine contains "Sophos Management Database" or ProcessCommandLine contains "Sophos Management Server" or ProcessCommandLine contains "Sophos Remote Management System" or ProcessCommandLine contains "Sophos Update Manager" or ProcessCommandLine contains "Threat Protection" or ProcessCommandLine contains "VirusScan" or ProcessCommandLine contains "Webroot SecureAnywhere" or ProcessCommandLine contains "Windows Defender")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1562"]
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
}