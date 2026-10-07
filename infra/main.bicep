// =============================================================================
// Azure Secure Web App Baseline
// -----------------------------------------------------------------------------
// Scenario: a small nonprofit needs a donor portal (web app + SQL database).
// Their auditor requires: no passwords in code or config, encrypted traffic
// only, least-privilege access, and centralized audit logs.
//
// Design goal: ZERO stored credentials.
//   - Azure SQL accepts Microsoft Entra ID logins only (SQL passwords disabled)
//   - The web app signs in to SQL with its own managed identity
//   - Any third-party secrets live in Key Vault, read via managed identity + RBAC
// =============================================================================

targetScope = 'resourceGroup'

// ----------------------------------------------------------------------------
// Parameters
// ----------------------------------------------------------------------------

@description('Short, lowercase app prefix used in resource names (e.g. donorportal).')
@minLength(3)
@maxLength(12)
param appName string

@description('Deployment environment. Controls SKU sizes and protection settings.')
@allowed([
  'dev'
  'prod'
])
param environment string = 'dev'

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Display name / UPN of the Microsoft Entra user or group that administers Azure SQL.')
param sqlEntraAdminLogin string

@description('Object ID of that Microsoft Entra user or group.')
param sqlEntraAdminObjectId string

@description('Whether the SQL admin is a single user or a group (a group is recommended for teams).')
@allowed([
  'User'
  'Group'
])
param sqlEntraAdminPrincipalType string = 'User'

@description('Optional third-party API key (e.g. payment processor). Stored only in Key Vault. Leave empty to skip.')
@secure()
param externalApiKey string = ''

@description('Days until the external API key secret expires (forces a rotation review).')
@minValue(30)
@maxValue(730)
param secretExpiryDays int = 365

@description('Do not set. Captures deployment time so secret expiry can be calculated.')
param deploymentTime string = utcNow('u')

@description('Enable Microsoft Defender for SQL (adds monthly cost; recommended for prod).')
param enableDefenderForSql bool = false

@description('Tags applied to every resource.')
param tags object = {
  project: 'secure-webapp-baseline'
  managedBy: 'bicep'
}

// ----------------------------------------------------------------------------
// Variables
// ----------------------------------------------------------------------------

var prefix = toLower(appName)
var suffix = uniqueString(resourceGroup().id)
var allTags = union(tags, { environment: environment })

var logAnalyticsName = 'log-${prefix}-${environment}'
var appInsightsName = 'appi-${prefix}-${environment}'
var planName = 'plan-${prefix}-${environment}'
var webAppName = 'app-${prefix}-${environment}-${suffix}'
var sqlServerName = 'sql-${prefix}-${environment}-${suffix}'
var sqlDatabaseName = 'appdb'
var keyVaultName = take('kv-${prefix}-${environment}-${suffix}', 24)
var externalApiKeySecretName = 'ExternalApiKey'

// Built-in role: Key Vault Secrets User (read secret values only)
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

// Environment sizing: one template, two cost profiles
var sizing = {
  dev: {
    planSku: 'B1'
    sqlSku: 'Basic'
    sqlTier: 'Basic'
    logRetentionDays: 30
    alwaysOn: false
    purgeProtection: false
  }
  prod: {
    planSku: 'P1v3'
    sqlSku: 'S1'
    sqlTier: 'Standard'
    logRetentionDays: 90
    alwaysOn: true
    purgeProtection: true
  }
}
var size = sizing[environment]

// ----------------------------------------------------------------------------
// Monitoring: every resource reports here
// ----------------------------------------------------------------------------

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2025-07-01' = {
  name: logAnalyticsName
  location: location
  tags: allTags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: size.logRetentionDays
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  tags: allTags
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

// ----------------------------------------------------------------------------
// Azure SQL: Entra-only authentication, TLS 1.2, auditing to Log Analytics
// ----------------------------------------------------------------------------

resource sqlServer 'Microsoft.Sql/servers@2025-01-01' = {
  // checkov:skip=CKV_AZURE_113: Public endpoint needed until private networking is added. Logins are Entra-only. See RISK-01.
  // checkov:skip=CKV_AZURE_24: Audit logs go to Log Analytics; retention is set on the workspace, not here. See RISK-05.
  // checkov:skip=CKV_AZURE_25: Defender for SQL is a cost decision, controlled by enableDefenderForSql. See RISK-04.
  name: sqlServerName
  location: location
  tags: allTags
  properties: {
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled' // see docs/accepted-risks.md (private endpoint is on the roadmap)
    administrators: {
      administratorType: 'ActiveDirectory'
      azureADOnlyAuthentication: true // SQL username/password logins are disabled
      login: sqlEntraAdminLogin
      sid: sqlEntraAdminObjectId
      tenantId: tenant().tenantId
      principalType: sqlEntraAdminPrincipalType
    }
  }
}

// Lets Azure-hosted services (the web app) reach the server. Internet clients stay blocked.
resource sqlAllowAzureServices 'Microsoft.Sql/servers/firewallRules@2025-01-01' = {
  parent: sqlServer
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource sqlDatabase 'Microsoft.Sql/servers/databases@2025-01-01' = {
  // checkov:skip=CKV_AZURE_23: False positive. Auditing is enabled at server level (sqlAuditing) and applies to every database.
  // checkov:skip=CKV_AZURE_25: Defender for SQL is controlled by enableDefenderForSql. See RISK-04.
  // checkov:skip=CKV_AZURE_26: Threat alerts route through Defender for Cloud when enabled. See RISK-04.
  // checkov:skip=CKV_AZURE_27: Threat alerts route through Defender for Cloud when enabled. See RISK-04.
  // checkov:skip=CKV_AZURE_229: Zone redundancy needs a higher tier; out of scope for this cost profile. See RISK-06.
  parent: sqlServer
  name: sqlDatabaseName
  location: location
  tags: allTags
  sku: {
    name: size.sqlSku
    tier: size.sqlTier
  }
  properties: {
    collation: 'SQL_Latin1_General_CP1_CI_AS'
  }
}

// Server-level auditing, sent to Azure Monitor (Log Analytics)
resource sqlAuditing 'Microsoft.Sql/servers/auditingSettings@2025-01-01' = {
  parent: sqlServer
  name: 'default'
  properties: {
    state: 'Enabled'
    isAzureMonitorTargetEnabled: true
  }
}

// Audit events are emitted from the master database
resource sqlMasterDb 'Microsoft.Sql/servers/databases@2025-01-01' existing = {
  // checkov:skip=CKV_AZURE_23: False positive. This is a reference to the built-in master database, not a new resource.
  // checkov:skip=CKV_AZURE_25: False positive. This is a reference to the built-in master database, not a new resource.
  parent: sqlServer
  name: 'master'
}

// 2021-05-01-preview is the current API for diagnostic settings (the linter's only alternative is older).
#disable-next-line use-recent-api-versions
resource sqlAuditDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'sql-audit-to-log-analytics'
  scope: sqlMasterDb
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        category: 'SQLSecurityAuditEvents'
        enabled: true
      }
    ]
  }
  dependsOn: [
    sqlAuditing
  ]
}

resource sqlDefender 'Microsoft.Sql/servers/securityAlertPolicies@2025-01-01' = if (enableDefenderForSql) {
  parent: sqlServer
  name: 'Default'
  properties: {
    state: 'Enabled'
  }
}

// ----------------------------------------------------------------------------
// Key Vault: RBAC permissions, soft delete, audit logs
// ----------------------------------------------------------------------------

resource keyVault 'Microsoft.KeyVault/vaults@2025-05-01' = {
  // checkov:skip=CKV_AZURE_109: Public endpoint needed until private networking is added. Access is RBAC-only. See RISK-02.
  // checkov:skip=CKV_AZURE_189: Public endpoint needed until private networking is added. Access is RBAC-only. See RISK-02.
  // checkov:skip=CKV_AZURE_110: Purge protection is ON in prod. Off in dev so lab vaults can be cleaned up. See RISK-03.
  // checkov:skip=CKV_AZURE_42: Soft delete is always on; purge protection is on in prod. See RISK-03.
  name: keyVaultName
  location: location
  tags: allTags
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true // Azure RBAC instead of legacy access policies
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: size.purgeProtection ? true : null // irreversible once on, so prod only
    publicNetworkAccess: 'Enabled' // see docs/accepted-risks.md
  }
}

resource externalApiKeySecret 'Microsoft.KeyVault/vaults/secrets@2025-05-01' = if (!empty(externalApiKey)) {
  // checkov:skip=CKV_AZURE_41: False positive. Expiry IS set below; Checkov can't read conditional resources.
  // checkov:skip=CKV_AZURE_114: False positive. contentType IS set below; Checkov can't read conditional resources.
  parent: keyVault
  name: externalApiKeySecretName
  properties: {
    value: externalApiKey
    contentType: 'text/plain'
    attributes: {
      exp: dateTimeToEpoch(dateTimeAdd(deploymentTime, 'P${secretExpiryDays}D'))
    }
  }
}

#disable-next-line use-recent-api-versions
resource keyVaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'kv-audit-to-log-analytics'
  scope: keyVault
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        category: 'AuditEvent' // who read which secret, when
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// ----------------------------------------------------------------------------
// App Service: hardened Linux web app with a managed identity
// ----------------------------------------------------------------------------

resource appServicePlan 'Microsoft.Web/serverfarms@2024-11-01' = {
  // checkov:skip=CKV_AZURE_225: Zone redundancy needs 3+ premium instances; out of scope for this cost profile. See RISK-06.
  name: planName
  location: location
  tags: allTags
  kind: 'linux'
  sku: {
    name: size.planSku
  }
  properties: {
    reserved: true // required for Linux
  }
}

var baseAppSettings = [
  {
    name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
    value: appInsights.properties.ConnectionString
  }
  {
    // No password: the app authenticates with its managed identity
    name: 'SQL_CONNECTION_STRING'
    value: 'Server=tcp:${sqlServer.properties.fullyQualifiedDomainName},1433;Database=${sqlDatabaseName};Authentication=Active Directory Managed Identity;Encrypt=True;TrustServerCertificate=False;'
  }
  {
    name: 'NODE_ENV'
    value: environment == 'prod' ? 'production' : 'development'
  }
]

var secretAppSettings = empty(externalApiKey) ? [] : [
  {
    // A pointer to the vault, not the secret itself
    name: 'EXTERNAL_API_KEY'
    value: '@Microsoft.KeyVault(VaultName=${keyVault.name};SecretName=${externalApiKeySecretName})'
  }
]

resource webApp 'Microsoft.Web/sites@2024-11-01' = {
  // checkov:skip=CKV_AZURE_222: This is a public donor-facing website, so public access is the requirement.
  // checkov:skip=CKV_AZURE_17: Client certificates (mTLS) don't apply to a public site visited by browsers.
  // checkov:skip=CKV_AZURE_212: Multi-instance failover is a cost decision. See RISK-06.
  name: webAppName
  location: location
  tags: allTags
  kind: 'app,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    clientAffinityEnabled: false
    siteConfig: {
      linuxFxVersion: 'NODE|20-lts'
      minTlsVersion: '1.2'
      scmMinTlsVersion: '1.2'
      ftpsState: 'Disabled'
      http20Enabled: true
      remoteDebuggingEnabled: false
      alwaysOn: size.alwaysOn
      healthCheckPath: '/'
      appSettings: concat(baseAppSettings, secretAppSettings)
    }
  }
  dependsOn: [
    externalApiKeySecret
  ]
}

// Turn off username/password publishing (FTP and Kudu/SCM). Deploy with Entra ID instead.
resource webAppFtpAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-11-01' = {
  parent: webApp
  name: 'ftp'
  properties: {
    allow: false
  }
}

resource webAppScmAuth 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2024-11-01' = {
  parent: webApp
  name: 'scm'
  properties: {
    allow: false
  }
}

#disable-next-line use-recent-api-versions
resource webAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'app-logs-to-log-analytics'
  scope: webApp
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        category: 'AppServiceHTTPLogs'
        enabled: true
      }
      {
        category: 'AppServiceConsoleLogs'
        enabled: true
      }
      {
        category: 'AppServiceAuditLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// ----------------------------------------------------------------------------
// Least privilege: the web app may READ secrets in this one vault, nothing more
// ----------------------------------------------------------------------------

resource webAppKeyVaultAccess 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, webApp.id, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
    principalId: webApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// ----------------------------------------------------------------------------
// Outputs (used by scripts/Deploy.ps1)
// ----------------------------------------------------------------------------

output webAppName string = webApp.name
output webAppUrl string = 'https://${webApp.properties.defaultHostName}'
output webAppPrincipalId string = webApp.identity.principalId
output sqlServerName string = sqlServer.name
output sqlServerFqdn string = sqlServer.properties.fullyQualifiedDomainName
output sqlDatabaseName string = sqlDatabase.name
output keyVaultName string = keyVault.name
output logAnalyticsWorkspaceName string = logAnalytics.name
