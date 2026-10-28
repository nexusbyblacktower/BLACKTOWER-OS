import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { Pool, type PoolConfig } from 'pg';
import * as schema from './schema.ts';

declare global {
  var _neonPostgresPool: Pool | undefined;
  var _neonPostgresPoolUrl: string | undefined;
}

export interface ValidatedNeonPoolConfig extends PoolConfig {
  connectionString: string;
  ssl: {
    rejectUnauthorized: true;
  };
}

/**
 * Checks whether the canonical Neon PostgreSQL connection variable (DATABASE_URL)
 * is present and valid on the server without exposing secret values.
 */
export function isDatabaseConfigured(
  env: Record<string, string | undefined> = process.env
): boolean {
  const raw = env.DATABASE_URL?.trim();
  return Boolean(raw && /^postgres(ql)?:\/\//i.test(raw));
}

/**
 * Resolves and validates the canonical Neon PostgreSQL connection configuration
 * exclusively from DATABASE_URL.
 *
 * Fails closed with a clear server-side configuration error if DATABASE_URL is
 * missing or malformed. Never falls back to any alternate database provider.
 */
export function resolveNeonPoolConfig(
  env: Record<string, string | undefined> = process.env
): ValidatedNeonPoolConfig {
  const rawUrl = env.DATABASE_URL?.trim();
  if (!rawUrl) {
    throw new Error(
      'FATAL_DATABASE_CONFIG_MISSING: DATABASE_URL is required for Neon PostgreSQL connection. Fail-closed policy active.'
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(
      'FATAL_DATABASE_CONFIG_INVALID: DATABASE_URL is not a valid PostgreSQL URI.'
    );
  }

  if (parsed.protocol !== 'postgresql:' && parsed.protocol !== 'postgres:') {
    throw new Error(
      'FATAL_DATABASE_CONFIG_INVALID: DATABASE_URL must use the postgresql:// or postgres:// protocol.'
    );
  }

  if (!parsed.hostname) {
    throw new Error(
      'FATAL_DATABASE_CONFIG_INVALID: DATABASE_URL must include a database hostname.'
    );
  }

  return {
    connectionString: rawUrl,
    ssl: {
      rejectUnauthorized: true,
    },
    max: 10,
    connectionTimeoutMillis: 15000,
  };
}

/**
 * Creates or returns the Neon PostgreSQL connection pool resolved exclusively from DATABASE_URL.
 * Fails closed if DATABASE_URL is missing.
 */
export function createPool(
  env: Record<string, string | undefined> = process.env
): Pool {
  const config = resolveNeonPoolConfig(env);

  if (env === process.env) {
    if (
      !global._neonPostgresPool ||
      global._neonPostgresPoolUrl !== config.connectionString
    ) {
      global._neonPostgresPool = new Pool(config);
      global._neonPostgresPoolUrl = config.connectionString;
      global._neonPostgresPool.on('error', (err) => {
        console.error(
          'Unexpected error on idle Neon PostgreSQL pool client:',
          err.message
        );
      });
    }
    return global._neonPostgresPool;
  }

  return new Pool(config);
}

export function getDb(): NodePgDatabase<typeof schema> {
  return drizzle(createPool(process.env), { schema });
}

export const db: NodePgDatabase<typeof schema> = new Proxy(
  {} as NodePgDatabase<typeof schema>,
  {
    get(_target, prop, receiver) {
      const instance = getDb();
      const value = Reflect.get(instance, prop, receiver);
      return typeof value === 'function' ? value.bind(instance) : value;
    },
  }
);
