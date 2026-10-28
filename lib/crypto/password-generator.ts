import { SecurityAbortError } from './vault-crypto.ts';

export interface PasswordGeneratorConfig {
  length: number; // 8 - 64
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  excludeAmbiguous?: boolean;
}

export interface GeneratedPasswordResult {
  password: string;
  entropyBits: number;
  charsetSize: number;
  strengthLabel: 'Weak' | 'Moderate' | 'Strong' | 'Brutal';
  estimatedOfflineCrackTime: string;
  telemetry: {
    csprngSource: 'WebCrypto API (crypto.getRandomValues)';
    methodology: 'Rejection Sampling (Modulo-Bias Eliminated) + Unbiased Fisher-Yates';
    rejectionDraws: number;
    totalDraws: number;
  };
}

const CHARSETS = {
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  uppercaseUnambiguous: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  lowercaseUnambiguous: 'abcdefghijkmnopqrstuvwxyz',
  numbers: '0123456789',
  numbersUnambiguous: '23456789',
  symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?',
};

/**
 * Generates an unbiased random integer in [0, maxExclusive) using rejection sampling
 * over CSPRNG bytes so modulo bias is strictly zero.
 */
export function getUnbiasedRandomIndex(maxExclusive: number): { index: number; rejections: number } {
  if (maxExclusive <= 0 || maxExclusive > 256) {
    throw new SecurityAbortError('CSPRNG_INVALID_RANGE', 'Charset range must be between 1 and 256');
  }
  const limit = 256 - (256 % maxExclusive);
  const buf = new Uint8Array(1);
  let rejections = 0;

  while (true) {
    globalThis.crypto.getRandomValues(buf);
    const val = buf[0];
    if (val < limit) {
      buf[0] = 0;
      return { index: val % maxExclusive, rejections };
    }
    rejections += 1;
  }
}

export function estimateCrackTime(entropyBits: number): {
  strengthLabel: GeneratedPasswordResult['strengthLabel'];
  estimatedOfflineCrackTime: string;
} {
  // Assume fast offline attacker evaluating 10^10 Argon2id/hash guesses per second cluster
  if (entropyBits < 50) {
    return { strengthLabel: 'Weak', estimatedOfflineCrackTime: 'Minutes to Hours' };
  }
  if (entropyBits < 72) {
    return { strengthLabel: 'Moderate', estimatedOfflineCrackTime: 'Years to Decades' };
  }
  if (entropyBits < 96) {
    return { strengthLabel: 'Strong', estimatedOfflineCrackTime: 'Centuries (2^72+ ops)' };
  }
  return { strengthLabel: 'Brutal', estimatedOfflineCrackTime: '> 10^15 Years (Astronomical)' };
}

export function generateSecurePassword(config: PasswordGeneratorConfig): GeneratedPasswordResult {
  const length = Math.max(8, Math.min(64, Math.floor(config.length)));
  const activeSets: string[] = [];

  if (config.uppercase) {
    activeSets.push(config.excludeAmbiguous ? CHARSETS.uppercaseUnambiguous : CHARSETS.uppercase);
  }
  if (config.lowercase) {
    activeSets.push(config.excludeAmbiguous ? CHARSETS.lowercaseUnambiguous : CHARSETS.lowercase);
  }
  if (config.numbers) {
    activeSets.push(config.excludeAmbiguous ? CHARSETS.numbersUnambiguous : CHARSETS.numbers);
  }
  if (config.symbols) {
    activeSets.push(CHARSETS.symbols);
  }

  if (activeSets.length === 0) {
    throw new SecurityAbortError('GENERATOR_NO_CHARSET', 'At least one character set must be selected');
  }

  const combinedPool = activeSets.join('');
  const chars: string[] = [];
  let totalRejections = 0;
  let totalDraws = 0;

  // Guarantee at least one character from each enabled set
  for (const set of activeSets) {
    const { index, rejections } = getUnbiasedRandomIndex(set.length);
    totalRejections += rejections;
    totalDraws += 1 + rejections;
    chars.push(set[index]);
  }

  // Fill remaining characters from the combined pool using rejection sampling
  for (let i = chars.length; i < length; i++) {
    const { index, rejections } = getUnbiasedRandomIndex(combinedPool.length);
    totalRejections += rejections;
    totalDraws += 1 + rejections;
    chars.push(combinedPool[index]);
  }

  // Unbiased Fisher-Yates shuffle
  for (let i = chars.length - 1; i > 0; i--) {
    const { index: j, rejections } = getUnbiasedRandomIndex(i + 1);
    totalRejections += rejections;
    totalDraws += 1 + rejections;
    const temp = chars[i];
    chars[i] = chars[j];
    chars[j] = temp;
  }

  const entropyBits = Number((length * Math.log2(combinedPool.length)).toFixed(1));
  const { strengthLabel, estimatedOfflineCrackTime } = estimateCrackTime(entropyBits);

  return {
    password: chars.join(''),
    entropyBits,
    charsetSize: combinedPool.length,
    strengthLabel,
    estimatedOfflineCrackTime,
    telemetry: {
      csprngSource: 'WebCrypto API (crypto.getRandomValues)',
      methodology: 'Rejection Sampling (Modulo-Bias Eliminated) + Unbiased Fisher-Yates',
      rejectionDraws: totalRejections,
      totalDraws,
    },
  };
}
