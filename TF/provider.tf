terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

variable "workspace_id" {
  type = string
  default = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/dummy/providers/Microsoft.OperationalInsights/workspaces/dummy"
}
