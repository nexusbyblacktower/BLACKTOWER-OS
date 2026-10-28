import type { Metadata } from 'next';
import { Space_Grotesk, Manrope, IBM_Plex_Mono } from 'next/font/google';
import './globals.css';

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-display',
});

const manrope = Manrope({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-sans',
});

const ibmPlexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'BLACKTOWER OS™ — The BLACKTOWER Ecosystem & Product Showcase',
  description:
    'BLACKTOWER OS™ — Main gateway and product showcase for the BLACKTOWER™ ecosystem, featuring BLACKTOWER VAULT™.',
  openGraph: {
    title: 'BLACKTOWER OS™ — The BLACKTOWER Ecosystem & Product Showcase',
    description:
      'Main gateway and product showcase for the BLACKTOWER™ ecosystem, featuring BLACKTOWER VAULT™.',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`dark ${spaceGrotesk.variable} ${manrope.variable} ${ibmPlexMono.variable}`}
    >
      <body className="bg-[#050505] text-[#F4F7F5] font-sans antialiased selection:bg-[#00FF66]/20 selection:text-[#00FF66] min-h-screen">
        {children}
      </body>
    </html>
  );
}
