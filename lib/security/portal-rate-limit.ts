interface RateLimitBucket {
  count: number;
  resetAt: number;
}

export interface PortalRateLimiterOptions {
  maxAttempts: number;
  windowMs: number;
}

export interface PortalRateLimitResult {
  allowed: boolean;
  retryAfterSeconds: number;
}

/**
 * Best-effort process-local login throttle for V1.
 * A durable distributed limiter should replace this when multiple application
 * instances are deployed. The limiter never stores passwords or tokens.
 */
export function createPortalRateLimiter(options: PortalRateLimiterOptions) {
  const buckets = new Map<string, RateLimitBucket>();
  const maxAttempts = Math.max(1, Math.floor(options.maxAttempts));
  const windowMs = Math.max(1_000, Math.floor(options.windowMs));

  return {
    check(key: string): PortalRateLimitResult {
      const now = Date.now();
      const existing = buckets.get(key);

      if (!existing || existing.resetAt <= now) {
        buckets.set(key, { count: 1, resetAt: now + windowMs });
        return { allowed: true, retryAfterSeconds: 0 };
      }

      if (existing.count >= maxAttempts) {
        return {
          allowed: false,
          retryAfterSeconds: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)),
        };
      }

      existing.count += 1;
      return { allowed: true, retryAfterSeconds: 0 };
    },

    clear(key: string): void {
      buckets.delete(key);
    },
  };
}

export const portalLoginRateLimiter = createPortalRateLimiter({
  maxAttempts: 5,
  windowMs: 10 * 60 * 1000,
});
