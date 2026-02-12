ALTER TABLE registry_namespaces ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'tenant-default';
ALTER TABLE registry_agents ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'tenant-default';

CREATE INDEX IF NOT EXISTS idx_registry_namespaces_tenant
  ON registry_namespaces(tenant_id, namespace);

CREATE INDEX IF NOT EXISTS idx_registry_agents_tenant
  ON registry_agents(tenant_id, namespace, status);
