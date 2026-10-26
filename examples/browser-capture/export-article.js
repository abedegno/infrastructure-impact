// Run in DevTools on a reviewed public vendor page. Inspect the article first.
// This saves the rendered article only; it does not export cookies or HTTP headers.
async function exportImpactArticle({ vendor, browserName, selector = 'main article' }) {
  if (location.protocol !== 'https:') throw new Error('An HTTPS source is required');
  const articles = [...document.querySelectorAll(selector)].filter(
    (el) => el.getClientRects().length && getComputedStyle(el).visibility !== 'hidden',
  );
  if (articles.length !== 1) throw new Error('Select exactly one visible main article');
  const rendered = articles[0].outerHTML;
  const bytes = new TextEncoder().encode(rendered);
  if (bytes.length > 2000000) throw new Error('Article exceeds capture limit');
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  const envelope = {
    schema_version: 1,
    vendor,
    source_url: location.href,
    captured_at: new Date().toISOString(),
    capture_method: 'browser_dom',
    capture_scope: 'visible_main_article',
    browser_name: browserName,
    rendered_html: rendered,
    rendered_sha256: [...new Uint8Array(digest)]
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(''),
  };
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(envelope, null, 2) + '\n'], { type: 'application/json' }),
  );
  const link = document.createElement('a');
  link.href = url;
  link.download = 'impact-browser-capture.json';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
// Example after inspecting the public Aruba Version history article:
// await exportImpactArticle({vendor: 'aruba', browserName: 'Chrome'});
