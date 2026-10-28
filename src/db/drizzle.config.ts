import { defineConfig } from 'drizzle-kit';
import * as dotenv from 'dotenv';

dotenv.config();

export function resolveDrizzleMigrationCredentials(
  env: Record<string, string | undefined> = process.env
): {
  url: string;
  ssl: { rejectUnauthorized: true };
} {
  const rawUrl = env.DATABASE_URL?.trim();
  if (!rawUrl) {
    throw new Error(
      'FATAL_MIGRATION_CONFIG_MISSING: DATABASE_URL is required for Neon PostgreSQL migrations. Fail-closed policy active.'
    );
  }
  if (!/^postgres(ql)?:\/\//i.test(rawUrl)) {
    throw new Error(
      'FATAL_MIGRATION_CONFIG_INVALID: DATABASE_URL must use the postgresql:// or postgres:// protocol.'
    );
  }
  return {
    url: rawUrl,
    ssl: { rejectUnauthorized: true },
  };
}

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
  schemaFilter: ['public'],
  dbCredentials: resolveDrizzleMigrationCredentials(process.env),
  verbose: true,
});
