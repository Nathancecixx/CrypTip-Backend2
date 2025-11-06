export const metadata = {
  title: 'Crypto Tip Jar',
  description: 'Non-custodial tips on Solana',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
