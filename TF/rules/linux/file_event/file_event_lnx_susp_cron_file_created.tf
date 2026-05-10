resource "azurerm_sentinel_alert_rule_scheduled" "file_event_lnx_susp_cron_file_created" {
  name                       = "file_event_lnx_susp_cron_file_created"
  log_analytics_workspace_id = var.workspace_id
  display_name               = "New Cron File Created"
  description                = <<DESC
    Detects the creation of cron files in Cron directories, which could indicate potential persistence mechanisms being established by an attacker. Note that not all cron file creations are malicious - legitimate system administration activities and software installations may also create cron files. This detection should be investigated in context, considering factors such as the user creating the file, the timing of creation, and the contents of the cron job. Focus investigation on unexpected cron files created by non-administrative users or during suspicious timeframes. Additionally, it is recommended to review the contents of the newly created cron files to assess their intent. Furthermore, it is suggested to baseline normal cron file creation and apply additional filters to reduce false positives based on the specific environment.

    Reference: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/file_event/file_event_lnx_susp_cron_file_created.yml

    False Positives:
    - Legitimate administrative tasks, package managers, containers, configuration management tools, cloud agents, or system maintenance operations might cause false positives. Apply baselining before deployment.
  DESC
  severity                   = "Low"
  query                      = <<QUERY
DeviceFileEvents
| where ((FolderPath startswith "/etc/cron.d/" or FolderPath startswith "/etc/cron.daily/" or FolderPath startswith "/etc/cron.hourly/" or FolderPath startswith "/etc/cron.monthly/" or FolderPath startswith "/etc/cron.weekly/" or FolderPath startswith "/var/spool/cron/crontabs/" or FolderPath startswith "/var/spool/cron/root") or (FolderPath contains "/etc/cron.allow" or FolderPath contains "/etc/cron.deny" or FolderPath contains "/etc/crontab")) and (not((FolderPath in~ ("/etc/cron.daily/apt", "/etc/cron.daily/dpkg", "/etc/cron.daily/passwd", "/etc/crontabs/root"))))
QUERY
  query_frequency            = "PT1H"
  query_period               = "PT1H"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5H"
  tactics                    = ["PrivilegeEscalation", "Execution", "Persistence"]
  techniques                 = ["T1053"]
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
    entity_type = "File"
    field_mapping {
      identifier  = "Directory"
      column_name = "FolderPath"
    }
  }
}