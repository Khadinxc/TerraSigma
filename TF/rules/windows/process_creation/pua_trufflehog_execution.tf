resource "azurerm_sentinel_alert_rule_scheduled" "pua_trufflehog_execution" {
  name                       = "pua_trufflehog_execution"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "PUA - TruffleHog Execution"
  description                = "Detects execution of TruffleHog, a tool used to search for secrets in different platforms like Git, Jira, Slack, SharePoint, etc. that could be used maliciously. While it is a legitimate tool, intended for use in CI pipelines and security assessments, It was observed in the Shai-Hulud malware campaign targeting npm packages to steal sensitive information. - Legitimate use of TruffleHog by security teams or developers."
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where FolderPath endswith "\\trufflehog.exe" or ((ProcessCommandLine contains " docker --image " or ProcessCommandLine contains " Git " or ProcessCommandLine contains " GitHub " or ProcessCommandLine contains " Jira " or ProcessCommandLine contains " Slack " or ProcessCommandLine contains " Confluence " or ProcessCommandLine contains " SharePoint " or ProcessCommandLine contains " s3 " or ProcessCommandLine contains " gcs ") and ProcessCommandLine contains " --results=verified")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["Discovery", "CredentialAccess"]
  techniques                 = ["T1083", "T1552"]
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
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}