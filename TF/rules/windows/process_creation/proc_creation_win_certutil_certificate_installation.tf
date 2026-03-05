resource "azurerm_sentinel_alert_rule_scheduled" "proc_creation_win_certutil_certificate_installation" {
  name                       = "proc_creation_win_certutil_certificate_installation"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Root Certificate Installed Via Certutil.EXE"
  description                = <<DESC
    Detects execution of "certutil" with the "addstore" flag in order to install a new certificate on the system. Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_certutil_certificate_installation.yml

    False Positives:
    - Help Desk or IT may need to manually add a corporate Root CA on occasion. Need to test if GPO push doesn't trigger FP
  DESC
  severity                   = "Medium"
  query                      = <<QUERY
DeviceProcessEvents
| where (ProcessCommandLine contains "-addstore" or ProcessCommandLine contains "/addstore" or ProcessCommandLine contains "–addstore" or ProcessCommandLine contains "—addstore" or ProcessCommandLine contains "―addstore") and ProcessCommandLine contains "root" and (FolderPath endswith "\\certutil.exe" or ProcessVersionInfoOriginalFileName =~ "CertUtil.exe")
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["DefenseEvasion"]
  techniques                 = ["T1553"]
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