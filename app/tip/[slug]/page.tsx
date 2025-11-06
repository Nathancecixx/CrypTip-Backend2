import { getPageByWallet } from '@/src/lib/db';

export const dynamic = 'force-dynamic';

export default async function TipPage({ params }: { params: { slug: string } }) {
  const page = await getPageByWallet(params.slug);
  if (!page) return <main style={{ padding: 24 }}>Not found</main>;
  const theme = page.theme_json || {};
  return (
    <main style={{ padding: 24 }}>
      <h1>Crypto Tip Jar</h1>
      <p>Template: {page.template_key}</p>
      <pre>{JSON.stringify(theme, null, 2)}</pre>
      <section style={{ marginTop: 24 }}>
        <a href={`https://phantom.app/ul/browse/cryptip.org/tip/${params.slug}`}>Open in Phantom</a>
      </section>
    </main>
  );
}
