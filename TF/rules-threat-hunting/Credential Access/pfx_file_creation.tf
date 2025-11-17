resource "azurerm_sentinel_alert_rule_scheduled" "pfx_file_creation" {
  name                       = "pfx_file_creation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PFX File Creation"
  description                = "Detects the creation of PFX files (Personal Information Exchange format). PFX files contain private keys and certificates bundled together, making them valuable targets for attackers seeking to: - Exfiltrate digital certificates for impersonation or signing malicious code - Establish persistent access through certificate-based authentication - Bypass security controls that rely on certificate validation Analysts should investigate PFX file creation events by examining which process created the PFX file and its parent process chain, as well as unusual locations outside standard certificate stores or development environments. - System administrators legitimately managing certificates and PKI infrastructure - Development environments where developers create test certificates for application signing - Automated certificate deployment tools and scripts used in enterprise environments - Software installation processes that include certificate provisioning (e.g., web servers, VPN clients) - Certificate backup and recovery operations performed by IT staff - Build systems and CI/CD pipelines that generate code signing certificates - Third-party applications that create temporary certificates for secure communications"
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where FolderPath endswith ".pfx" and (not((FolderPath startswith "C:\\Program Files\\CMake\\" or ((InitiatingProcessFolderPath in~ ("C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe", "C:\\Program Files (x86)\\Microsoft OneDrive\\OneDrive.exe")) and FolderPath endswith "\\OneDrive\\CodeSigning.pfx") or (FolderPath startswith "C:\\Program Files (x86)\\Microsoft Visual Studio\\" or FolderPath startswith "C:\\Program Files\\Microsoft Visual Studio\\"))))
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}