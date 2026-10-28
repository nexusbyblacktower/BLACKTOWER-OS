'use client';

import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { ArrowDown, LockKeyhole, Shield } from 'lucide-react';

interface VaultEcosystemTransitionProps {
  active: boolean;
  targetLabel?: string;
}

/**
 * Smooth, premium ecosystem transition overlay:
 * BLACKTOWER OS™
 *       ↓
 * BLACKTOWER VAULT™
 *
 * Preserves strict authentication boundaries: transitioning from BLACKTOWER OS™
 * into BLACKTOWER VAULT™ never bypasses Vault Master Password / Argon2id unlock.
 */
export default function VaultEcosystemTransition({
  active,
  targetLabel = 'BLACKTOWER VAULT™',
}: VaultEcosystemTransitionProps) {
  return (
    <AnimatePresence>
      {active && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.22, ease: 'easeOut' }}
          className="fixed inset-0 z-50 bg-[#050505]/95 backdrop-blur-md flex flex-col items-center justify-center px-6 select-none"
          role="status"
          aria-live="polite"
        >
          <motion.div
            initial={{ y: 12, opacity: 0 }}
            animate={{ y: 0, opacity: 1 }}
            transition={{ duration: 0.28, ease: 'easeOut' }}
            className="max-w-md w-full bg-[#0B0E11] border border-[#00FF66]/30 rounded-2xl p-8 text-center shadow-[0_0_48px_rgba(0,255,102,0.12)] space-y-5"
          >
            {/* Source Node: BLACKTOWER OS™ */}
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-md bg-[#07090B] border border-[#161B20] text-[11px] font-mono tracking-[0.2em] uppercase text-zinc-400">
              <Shield className="w-3.5 h-3.5 text-[#00FF66]" />
              <span>BLACKTOWER OS™</span>
            </div>

            {/* Connected Ecosystem Connector */}
            <div className="flex flex-col items-center justify-center py-1">
              <div className="w-px h-6 bg-gradient-to-b from-zinc-700 to-[#00FF66]" />
              <div className="w-7 h-7 rounded-full bg-[#00FF66]/10 border border-[#00FF66]/40 flex items-center justify-center my-1">
                <ArrowDown className="w-3.5 h-3.5 text-[#00FF66]" />
              </div>
              <div className="w-px h-6 bg-gradient-to-b from-[#00FF66] to-zinc-700" />
            </div>

            {/* Destination Node: BLACKTOWER VAULT™ */}
            <div className="space-y-2">
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-[#00FF66]/10 border border-[#00FF66]/35 text-xs font-mono tracking-[0.18em] uppercase text-[#00FF66] font-semibold">
                <LockKeyhole className="w-3.5 h-3.5 text-[#00FF66]" />
                <span>{targetLabel}</span>
              </div>
              <p className="text-xs text-zinc-400 leading-relaxed pt-1">
                Entering independent Vault boundary. Master Password authentication and client-side key derivation remain strictly enforced.
              </p>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
