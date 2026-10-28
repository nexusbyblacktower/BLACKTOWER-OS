/**
 * Authoritative BLACKTOWER VAULT™ & BLACKTOWER OS™ Design Token System.
 *
 * Brand Direction:
 * - BLACK / OBSIDIAN Canvas & Surfaces (#050505 / #0B0E11 / #07090B)
 * - BLACKTOWER NEON GREEN Primary Brand Accent (#00FF66)
 * - MINIMAL PREMIUM UI (Hairline structural borders, restrained neon-green highlights)
 *
 * Reused across both BLACKTOWER VAULT™ and BLACKTOWER OS™ so the entire ecosystem
 * shares one unified visual authority without blue or mixed-accent drift.
 */
export const BLACKTOWER_TOKENS = {
  colors: {
    canvas: '#050505',
    surfacePrimary: '#0B0E11',
    surfaceRecessed: '#07090B',
    surfaceElevated: '#10151A',
    borderSubtle: '#161B20',
    borderAccent: 'rgba(0, 255, 102, 0.32)',
    neonGreen: '#00FF66',
    neonGreenHover: '#22FF7A',
    neonGreenMuted: 'rgba(0, 255, 102, 0.10)',
    textPrimary: '#F4F7F5',
    textSecondary: '#9CA6A0',
    textMuted: '#5E6862',
  },
  shadows: {
    neonGlow: '0 0 24px rgba(0, 255, 102, 0.16)',
    cardElevation: '0 24px 64px -16px rgba(0, 0, 0, 0.85)',
  },
  classes: {
    canvasBg: 'bg-[#050505] text-[#F4F7F5]',
    cardSurface: 'bg-[#0B0E11] border border-[#161B20] rounded-xl',
    recessedInput:
      'bg-[#07090B] border border-[#161B20] rounded-lg text-white placeholder:text-zinc-600 focus:outline-none focus:border-[#00FF66] focus:ring-1 focus:ring-[#00FF66]/20 transition-colors',
    primaryButton:
      'bg-[#00FF66] hover:bg-[#22FF7A] active:bg-[#00E05A] text-[#050505] font-semibold rounded-lg shadow-[0_0_24px_rgba(0,255,102,0.16)] transition-all',
    secondaryButton:
      'bg-[#0B0E11] hover:bg-[#11161B] text-zinc-200 hover:text-[#00FF66] border border-[#161B20] hover:border-[#00FF66]/40 rounded-lg transition-colors',
    accentBadge:
      'bg-[#00FF66]/10 border border-[#00FF66]/30 text-[#00FF66]',
  },
} as const;
