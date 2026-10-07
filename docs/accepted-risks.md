# Accepted risks

Security scanners flag everything that *could* be stricter. Not every finding should be fixed right away: some fixes cost money, some don't apply to this workload, and a few findings are false positives.

This page records each decision so it is **visible, justified and revisitable** instead of silently ignored. Every Checkov suppression in [`infra/main.bicep`](../infra/main.bicep) and [`.checkov.yaml`](../.checkov.yaml) points back to an ID here.

| ID | Risk | Why it's accepted for now | What reduces the risk today | How to remove it |
|---|---|---|---|---|
| RISK-01 | Azure SQL has a public endpoint | Private networking (VNet + private endpoint + private DNS) adds cost and complexity beyond this baseline's scope | Entra-only logins (no passwords to steal or brute-force), TLS 1.2 minimum, only Azure services allowed through the firewall, admin access opened per-IP and removed automatically by `Grant-AppDatabaseAccess.ps1`, all logins audited | Add a VNet, private endpoint and App Service VNet integration; set `publicNetworkAccess: 'Disabled'` |
| RISK-02 | Key Vault has a public endpoint | Same as RISK-01 | Azure RBAC only (no access policies), the app's identity can read secrets in this vault only, every access logged to Log Analytics | Same private endpoint pattern as RISK-01 |
| RISK-03 | Key Vault purge protection is off in **dev** | Purge protection can never be turned off once enabled, and it reserves the vault name for 90 days. In a lab that gets torn down often, that blocks redeploying | Soft delete is always on (90 days), so deleted secrets can be recovered. Purge protection is **on in prod** | Set `environment=prod`, or set `purgeProtection: true` for dev in `main.bicep` |
| RISK-04 | Microsoft Defender for SQL (threat detection) off by default | It's a paid plan. The cost decision is left to the owner | One parameter turns it on: `enableDefenderForSql=true`. Auditing is always on | Deploy prod with `enableDefenderForSql=true` |
| RISK-05 | SQL audit retention is not set on the server | Logs go to Log Analytics, where retention is set on the workspace (30 days dev, 90 days prod). Checkov only understands storage-account retention | Workspace retention, plus Log Analytics queries and alerts | Raise `logRetentionDays`, or add a storage-account audit target with long retention for compliance needs |
| RISK-06 | No zone redundancy or multi-instance failover | Requires premium SKUs and 3+ instances, which multiplies cost | Health check path configured. Prod uses `alwaysOn` and larger SKUs | Enable zone redundancy on the App Service plan and SQL database in prod |

## False positives (not risks)

| Check | Why it's a false positive |
|---|---|
| CKV_AZURE_23 (SQL auditing) on the database | Auditing is enabled once at server level (`sqlAuditing`), which covers every database. Checkov doesn't link child resources in Bicep |
| CKV_AZURE_23 / 25 on `master` | `sqlMasterDb` is a reference to Azure's built-in database, not a resource this template creates |
| CKV_AZURE_41 / 114 on the API key secret | Expiry and content type **are** set. Checkov can't read resources that are deployed conditionally (`if (...)`) |

## Not applicable to this workload

| Check | Reason |
|---|---|
| CKV_AZURE_222 (web app public access) | It's a public website for donors. Being reachable from the internet is the requirement |
| CKV_AZURE_17 (client certificates) | Mutual TLS is for machine-to-machine APIs, not a site visited in a browser |
