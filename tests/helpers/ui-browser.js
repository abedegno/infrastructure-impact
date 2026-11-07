const fs = require('fs'),
  vm = require('vm');
const web = 'infrastructure_impact/web/';
const base = JSON.parse(fs.readFileSync('tests/fixtures/kev-selection-cases.json')).base_report;
function browser(currentEvidence = false) {
  const nodes = new Map(),
    downloads = [],
    requests = [],
    blobs = new Map(),
    documentClicks = [];
  let blobId = 0,
    now = Date.parse(base.generated_at);
  const decode = (value) =>
    value
      .replaceAll('&quot;', '"')
      .replaceAll('&lt;', '<')
      .replaceAll('&gt;', '>')
      .replaceAll('&amp;', '&');
  class Element {
    constructor(tag = '', attrs = '') {
      this.tagName = tag.toUpperCase();
      this.listeners = {};
      this.dataset = {};
      this.attrs = {};
      for (const m of attrs.matchAll(/([\w-]+)(?:="([^"]*)")?/g))
        this.attrs[m[1]] = decode(m[2] || '');
      this.id = this.attrs.id || '';
      this.value = this.attrs.value || '';
      this.checked = Object.hasOwn(this.attrs, 'checked');
      this.disabled = Object.hasOwn(this.attrs, 'disabled');
      this.hidden = Object.hasOwn(this.attrs, 'hidden');
      this.href = this.attrs.href || '';
      this.download = this.attrs.download || '';
      this.ownerDocument = document;
      if (this.attrs['data-view']) this.dataset.view = this.attrs['data-view'];
    }
    set innerHTML(html) {
      this.html = html;
      parse(html, this);
    }
    get innerHTML() {
      return this.html || '';
    }
    set textContent(text) {
      this.text = String(text);
    }
    get textContent() {
      return this.text || '';
    }
    addEventListener(type, handler) {
      (this.listeners[type] ||= []).push(handler);
    }
    setAttribute(key, value) {
      this.attrs[key] = value;
    }
    removeAttribute(key) {
      delete this.attrs[key];
    }
    querySelector(selector) {
      return document.querySelector(selector);
    }
    focus() {
      document.activeElement = this;
    }
    close() {}
    showModal() {}
    click() {
      if (this.download && this.href.startsWith('blob:'))
        downloads.push({ name: this.download, blob: blobs.get(this.href) });
      return this.fire('click');
    }
    closest(selector) {
      return selector.split(',').includes('#' + this.id) ? this : null;
    }
    fire(type) {
      const event = {
        target: this,
        preventDefault() {},
        stopPropagation() {},
        stopImmediatePropagation() {},
      };
      const handlers = [];
      for (let e = this; e; e = e.parentElement) handlers.push(...(e.listeners[type] || []));
      if (type === 'click') handlers.push(...documentClicks);
      return Promise.all(handlers.map((fn) => fn(event)));
    }
  }
  const document = {
    baseURI: 'https://example.test/',
    activeElement: null,
    querySelector(selector) {
      return nodes.get(selector) || null;
    },
    querySelectorAll(selector) {
      return selector === '[data-view]' ? [...nodes.values()].filter((n) => n.dataset.view) : [];
    },
    createElement(tag) {
      return new Element(tag);
    },
    addEventListener(type, fn) {
      if (type === 'click') documentClicks.push(fn);
    },
  };
  function parse(html, parent = null) {
    for (const m of html.matchAll(
      /<(input|select|button|section|div|span|a|dialog|option)\b([^>]*)>/g,
    )) {
      const e = new Element(m[1], m[2]);
      e.parentElement = parent;
      if (e.id) nodes.set('#' + e.id, e);
      if (e.dataset.view) nodes.set('[data-view="' + e.dataset.view + '"]', e);
      if (m[1] === 'option' && e.value === 'benchmark')
        nodes.set('#cohort option[value="benchmark"]', e);
    }
    for (const m of html.matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select>/g)) {
      const id = /id="([^"]+)"/.exec(m[1]);
      const selected =
        /<option\b[^>]*value="([^"]*)"[^>]*selected/.exec(m[2]) ||
        /<option\b[^>]*value="([^"]*)"/.exec(m[2]);
      if (id && selected) nodes.get('#' + id[1]).value = decode(selected[1]);
    }
  }
  parse(fs.readFileSync(web + 'index.html', 'utf8'));
  class Clock extends Date {
    constructor(...args) {
      super(...(args.length ? args : [now]));
    }
    static now() {
      return now;
    }
  }
  class BlobURL extends URL {
    static createObjectURL(blob) {
      const url = 'blob:' + ++blobId;
      blobs.set(url, blob);
      return url;
    }
    static revokeObjectURL() {}
  }
  const window = {};
  const context = {
    window,
    document,
    location: { origin: 'https://example.test' },
    URL: BlobURL,
    URLSearchParams,
    Blob,
    Response,
    TextEncoder,
    TextDecoder,
    Date: Clock,
    Set,
    Map,
    console,
    setTimeout: () => {},
  };
  context.fetch = window.fetch = (url) =>
    new Promise((resolve, reject) => requests.push({ url, resolve, reject }));
  vm.createContext(context);
  context.createStaticDelivery = async () => async () => ({ changes: [] });
  for (const file of [
    'lossless-json.js',
    ...(currentEvidence ? ['switching-contracts.js', 'current-evidence.js'] : []),
    'kev.js',
    'research-dossiers.js',
    'snapshot.js',
  ])
    vm.runInContext(fs.readFileSync(web + file, 'utf8'), context);
  vm.runInContext(fs.readFileSync(web + 'app.js', 'utf8'), context);
  const evaluate = (code) => vm.runInContext(code, context);
  return {
    nodes,
    requests,
    downloads,
    context,
    evaluate,
    advance(ms) {
      now += ms;
    },
    async settle() {
      for (let i = 0; i < 15; i++) await Promise.resolve();
    },
  };
}
module.exports = { browser };
