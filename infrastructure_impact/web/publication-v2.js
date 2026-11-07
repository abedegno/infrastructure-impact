/* Bounded, generation-bound publication token reader. */
(() => {
  const json = window.InfrastructureJSON,
    encoder = new TextEncoder();
  const fail = (message) => {
    throw Error('Publication v2: ' + message);
  };
  function integer(n, min = 0) {
    if (!Number.isSafeInteger(n) || n < min) fail('unsafe transport index');
    return n;
  }
  function literal(s) {
    if (typeof s !== 'string' || /[\uD800-\uDFFF]/u.test(s)) fail('invalid Unicode');
    return s;
  }
  const ownedTables = new WeakMap();
  function tables(strings, shapes) {
    if (!Array.isArray(strings) || !Array.isArray(shapes)) fail('invalid tables');
    strings.forEach(literal);
    const seen = new Set();
    for (const shape of shapes) {
      if (!Array.isArray(shape) || new Set(shape).size !== shape.length)
        fail('duplicate shape keys');
      shape.forEach(literal);
      const key = JSON.stringify(shape);
      if (seen.has(key)) fail('duplicate shape');
      seen.add(key);
    }
  }
  function stringCost(s, ascii = false) {
    literal(s);
    let total = 2;
    for (const c of s) {
      const code = c.codePointAt(0);
      total +=
        c === '"' || c === '\\' || '\b\f\n\r\t'.includes(c)
          ? 2
          : code < 32 || (ascii && code >= 127)
            ? code > 65535
              ? 12
              : 6
            : code < 128
              ? 1
              : code < 2048
                ? 2
                : code < 65536
                  ? 3
                  : 4;
    }
    return total;
  }
  function quote(s, ascii) {
    const raw = JSON.stringify(literal(s));
    return ascii
      ? raw.replace(
          /[\u007f-\uffff]/g,
          (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'),
        )
      : raw;
  }
  async function* streamTokens(tokens, strings, shapes, options = {}) {
    if (ownedTables.get(strings) !== shapes) tables(strings, shapes);
    const state = options.state || {
      used: 0,
      max: Math.min(integer(options.max_bytes ?? 1000000000), 1000000000),
      deadline: options.deadline ?? Date.now() + 300000,
    };
    const iterator = tokens[Symbol.asyncIterator]?.() || tokens[Symbol.iterator]();
    const ascii = options.serialization === 'ascii';
    if (options.serialization && !['logical', 'ascii'].includes(options.serialization))
      fail('serialization');
    function charge(size) {
      if (options.signal?.aborted) fail('cancelled');
      if (Date.now() > state.deadline) fail('stream deadline');
      if (size > state.max - state.used) fail('decoded byte budget');
      state.used += size;
    }
    function emit(raw, canonical = raw) {
      if (options.signal?.aborted) fail('cancelled');
      if (Date.now() > state.deadline) fail('stream deadline');
      const size = Math.max(encoder.encode(raw).length, encoder.encode(canonical).length);
      charge(size);
      options.observer?.(canonical);
      return raw;
    }
    function quoted(s) {
      charge(Math.max(stringCost(s), stringCost(s, ascii)));
      const raw = quote(s, ascii);
      options.observer?.(quote(s, false));
      return raw;
    }
    async function nextToken() {
      if (options.signal?.aborted) fail('cancelled');
      const remaining = state.deadline - Date.now();
      if (remaining <= 0) fail('stream deadline');
      let timer, abort;
      try {
        return await Promise.race([
          iterator.next(),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(Error('Publication v2: stream deadline')), remaining);
            if (options.signal) {
              abort = () => reject(Error('Publication v2: cancelled'));
              options.signal.addEventListener('abort', abort, { once: true });
            }
          }),
        ]);
      } finally {
        clearTimeout(timer);
        if (abort) options.signal.removeEventListener('abort', abort);
      }
    }
    async function* node(depth, path) {
      if (depth > 64) fail('decoder depth');
      const entry = await nextToken();
      if (entry.done) fail('truncated node');
      const t = entry.value;
      if (t === null || typeof t === 'boolean') yield emit(String(t));
      else if (typeof t === 'number') {
        integer(-t - 2);
        if (t < -Number.MAX_SAFE_INTEGER || -t - 2 >= strings.length) fail('string reference');
        const s = strings[-t - 2];
        yield quoted(s);
      } else if (Array.isArray(t) && t.length === 1) {
        const i = integer(t[0]);
        if (i >= shapes.length) fail('shape reference');
        const keys = shapes[i];
        if (keys.length * 5 + 2 > state.max - state.used) fail('object minimum budget');
        yield emit('{');
        for (let k = 0; k < keys.length; k++) {
          if (k) yield emit(',');
          yield quoted(keys[k]);
          yield emit(':');
          yield* node(depth + 1, [...path, keys[k]]);
        }
        yield emit('}');
      } else if (Array.isArray(t) && t.length === 2 && t[0] === -1) {
        const n = integer(t[1]);
        if ((n ? n * 2 + 1 : 2) > state.max - state.used) fail('array minimum budget');
        yield emit('[');
        for (let i = 0; i < n; i++) {
          if (i) yield emit(',');
          yield* node(depth + 1, [...path, i]);
        }
        yield emit(']');
      } else if (Array.isArray(t) && t.length === 3 && t[0] === -2) {
        const [_, kind, lexeme] = t;
        if (typeof lexeme !== 'string') fail('numeric lexeme');
        charge(lexeme.length);
        const grammar =
          kind === 'i'
            ? /^-?(?:0|[1-9]\d*)$/
            : kind === 'f'
              ? /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/
              : null;
        if (
          typeof lexeme !== 'string' ||
          !grammar?.test(lexeme) ||
          (kind === 'f' && !Number.isFinite(Number(lexeme)))
        )
          fail('numeric lexeme');
        options.observer?.(lexeme);
        yield lexeme;
      } else if (Array.isArray(t) && t.length === 2 && t[0] === -3) {
        if (
          options.root !== 'switching-comparison.json' ||
          JSON.stringify(path) !== '["inputs","evidence"]' ||
          t[1] !== 'switching-evidence.json' ||
          !options.aliases
        )
          fail('forbidden root alias');
        yield* streamTokens(await options.aliases(t[1]), strings, shapes, {
          ...options,
          state,
          root: t[1],
          aliases: null,
          depth,
        });
      } else fail('invalid token');
    }
    yield* node(options.depth ?? 0, options.path ?? []);
    if (!(await nextToken()).done) fail('extra node');
  }
  async function decodeTokens(tokens, strings, shapes, options = {}) {
    const pieces = [];
    for await (const chunk of streamTokens(tokens, strings, shapes, {
      max_bytes: 128000000,
      ...options,
    }))
      pieces.push(chunk);
    return pieces.join('');
  }
  function descriptor(d) {
    if (
      !d ||
      Object.keys(d).sort().join(',') !== 'bytes,path,sha256' ||
      !/^data\/v2\/[a-f0-9]{64}\.json$/.test(d.path) ||
      d.path !== `data/v2/${d.sha256}.json` ||
      integer(d.bytes, 1) > 8000000
    )
      fail('descriptor');
    return d;
  }
  function range(r) {
    if (
      !r ||
      Object.keys(r).sort().join(',') !==
        'end_token,first_token,logical_bytes,logical_sha256,root' ||
      !/^(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+(?:\.json)?$/.test(r.root) ||
      integer(r.first_token) >= integer(r.end_token, 1) ||
      !/^([a-f0-9]{64})$/.test(r.logical_sha256)
    )
      fail('range');
    integer(r.logical_bytes, 1);
    return r;
  }
  async function digest(raw) {
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)), (b) =>
      b.toString(16).padStart(2, '0'),
    ).join('');
  }
  function createHash() {
    const constants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
      0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2,
    ];
    const hash = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
      0x5be0cd19,
    ];
    const rotate = (v, n) => (v >>> n) | (v << (32 - n));
    let tail = [],
      length = 0;
    function block(bytes) {
      const words = [];
      for (let i = 0; i < 16; i++)
        words[i] =
          (bytes[i * 4] << 24) |
          (bytes[i * 4 + 1] << 16) |
          (bytes[i * 4 + 2] << 8) |
          bytes[i * 4 + 3];
      for (let i = 16; i < 64; i++) {
        const a = words[i - 15],
          b = words[i - 2];
        words[i] =
          (words[i - 16] +
            (rotate(a, 7) ^ rotate(a, 18) ^ (a >>> 3)) +
            words[i - 7] +
            (rotate(b, 17) ^ rotate(b, 19) ^ (b >>> 10))) |
          0;
      }
      let [a, b, c, d, e, f, g, h] = hash;
      for (let i = 0; i < 64; i++) {
        const t1 =
          (h +
            (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) +
            ((e & f) ^ (~e & g)) +
            constants[i] +
            words[i]) |
          0;
        const t2 =
          ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        [a, b, c, d, e, f, g, h] = [(t1 + t2) | 0, a, b, c, (d + t1) | 0, e, f, g];
      }
      [a, b, c, d, e, f, g, h].forEach((v, i) => {
        hash[i] = (hash[i] + v) | 0;
      });
    }
    function feed(raw) {
      for (const b of raw) {
        tail.push(b);
        if (tail.length === 64) {
          block(tail);
          tail = [];
        }
      }
    }
    return {
      update(text) {
        const raw = encoder.encode(text);
        length += raw.length;
        feed(raw);
      },
      digest() {
        const bits = BigInt(length) * 8n;
        feed([128]);
        while (tail.length !== 56) feed([0]);
        const size = [];
        for (let i = 7; i >= 0; i--) size.push(Number((bits >> BigInt(i * 8)) & 255n));
        feed(size);
        return hash.map((v) => (v >>> 0).toString(16).padStart(8, '0')).join('');
      },
    };
  }
  function freeze(value) {
    if (value && typeof value === 'object' && !Object.isFrozen(value)) {
      Object.values(value).forEach(freeze);
      Object.freeze(value);
    }
    return value;
  }
  async function open(fetchPart, catalog, identity, limits = {}) {
    catalog = freeze(json.clone(catalog));
    identity = freeze(
      json.clone({ publication: identity.publication, generated_at: identity.generated_at }),
    );
    window.InfrastructureSwitchingContracts.validate('publication-v2.json', catalog);
    if (
      catalog.publication.id !== identity.publication.id ||
      catalog.generated_at !== identity.generated_at ||
      catalog.publication.advisory_schema_version !== identity.publication.advisory_schema_version
    )
      fail('mixed generations');
    const cache = new Map(),
      pending = new Map(),
      waiters = [];
    let active = 0,
      bytes = 0;
    const maxCache = Math.min(integer(limits.cache_bytes ?? 16000000), 16000000);
    async function acquire() {
      if (active >= 6) await new Promise((resolve) => waiters.push(resolve));
      else active++;
    }
    function release() {
      const next = waiters.shift();
      if (next) next();
      else active--;
    }
    async function raw(d, signal) {
      descriptor(d);
      if (cache.has(d.path)) {
        const value = cache.get(d.path);
        cache.delete(d.path);
        cache.set(d.path, value);
        return value;
      }
      if (pending.has(d.path)) return pending.get(d.path);
      const promise = (async () => {
        await acquire();
        await limits.requestSlots?.acquire();
        const controller = new AbortController();
        const abort = () => controller.abort();
        signal?.addEventListener('abort', abort, { once: true });
        let timer;
        const expired = new Promise((_, reject) => {
          timer = setTimeout(
            () => {
              controller.abort();
              reject(Error('Publication v2: fetch deadline'));
            },
            Math.min(integer(limits.fetch_timeout_ms ?? 300000, 1), 300000),
          );
        });
        try {
          if (signal?.aborted) fail('cancelled');
          const response = await Promise.race([
            fetchPart(d.path, { signal: controller.signal }),
            expired,
          ]);
          if (!response.ok) fail('part unavailable');
          let value;
          if (response.body?.getReader) {
            const reader = response.body.getReader(),
              pieces = [];
            let size = 0;
            try {
              for (;;) {
                const part = await Promise.race([reader.read(), expired]);
                if (part.done) break;
                size += part.value.length;
                if (size > d.bytes) {
                  await reader.cancel();
                  fail('part size');
                }
                pieces.push(part.value);
              }
              value = new Uint8Array(size);
              let offset = 0;
              for (const piece of pieces) {
                value.set(piece, offset);
                offset += piece.length;
              }
            } finally {
              reader.releaseLock();
            }
          } else value = new Uint8Array(await Promise.race([response.arrayBuffer(), expired]));
          if (value.length !== d.bytes || (await digest(value)) !== d.sha256)
            fail('part fingerprint');
          if (value.length <= maxCache) {
            while (bytes + value.length > maxCache) {
              const key = cache.keys().next().value;
              bytes -= cache.get(key).length;
              cache.delete(key);
            }
            cache.set(d.path, value);
            bytes += value.length;
          }
          return value;
        } finally {
          clearTimeout(timer);
          signal?.removeEventListener('abort', abort);
          limits.requestSlots?.release();
          release();
        }
      })();
      pending.set(d.path, promise);
      try {
        return await promise;
      } finally {
        pending.delete(d.path);
      }
    }
    async function read(d, kind, signal) {
      const value = json.parseStrict(
        new TextDecoder('utf-8', { fatal: true }).decode(await raw(d, signal)),
      );
      window.InfrastructureSwitchingContracts.validate(
        'publication-v2.json',
        value,
        '/$defs/envelope',
      );
      if (
        value.publication.id !== identity.publication.id ||
        value.publication.advisory_schema_version !==
          identity.publication.advisory_schema_version ||
        value.generated_at !== identity.generated_at ||
        value.kind !== kind
      )
        fail('mixed generation or kind');
      return value.data;
    }
    let tablePromise;
    async function getTables() {
      if (!tablePromise)
        tablePromise = (async () => {
          const result = [];
          for (const [kind, entries] of [
            ['strings', catalog.strings],
            ['shapes', catalog.shapes],
          ]) {
            const rows = [];
            let size = 0;
            for (const entry of entries) {
              if (entry.first !== rows.length) fail('table contiguity');
              const data = await read(entry.part, kind);
              if (data.length !== entry.count) fail('table count');
              for (const item of data) {
                size += encoder.encode(JSON.stringify(item)).length;
                if (size > 128000000) fail('table decoded budget');
                rows.push(item);
              }
            }
            result.push(rows);
          }
          tables(...result);
          freeze(result);
          ownedTables.set(result[0], result[1]);
          return result;
        })();
      return tablePromise;
    }
    const roots = new Map();
    async function root(name) {
      if (!Object.hasOwn(catalog.roots, name)) fail('unknown root');
      if (!roots.has(name))
        roots.set(
          name,
          (async () => {
            const data = await read(catalog.roots[name], 'root');
            if (data.name !== name) fail('root name');
            let end = 0;
            for (const page of data.pages) {
              if (page.first_token !== end) fail('page contiguity');
              integer(page.decoded_upper_bound, 1);
              end += integer(page.count, 1);
            }
            if (end !== data.token_count) fail('root token count');
            return data;
          })(),
        );
      return roots.get(name);
    }
    let tokenPage = null; // One verified decoded page, never an unbounded page cache.
    async function* tokens(name, first = 0, end = null, options = {}) {
      const r = await root(name);
      end ??= r.token_count;
      integer(first);
      integer(end, 1);
      if (first >= end || end > r.token_count) fail('token range');
      for (const page of r.pages) {
        if (page.first_token >= end || page.first_token + page.count <= first) continue;
        if (page.decoded_upper_bound > Math.min(limits.page_bytes ?? 128000000, 128000000))
          fail('page expansion bound');
        const memo = tokenPage?.path === page.part.path ? tokenPage : null;
        const data = memo?.data ?? (await read(page.part, 'tokens', options.signal));
        if (data.length !== page.count) fail('page count');
        const [strings, shapes] = await getTables();
        let cost = memo?.cost ?? 0;
        if (!memo)
          for (const t of data) {
            if (t === null || typeof t === 'boolean') cost += String(t).length;
            else if (typeof t === 'number') {
              integer(-t - 2);
              if (-t - 2 >= strings.length) fail('string reference');
              cost += stringCost(strings[-t - 2]);
            } else if (Array.isArray(t) && t.length === 1) {
              const keys = shapes[integer(t[0])];
              if (!keys) fail('shape reference');
              cost +=
                2 + Math.max(0, keys.length - 1) + keys.reduce((n, k) => n + stringCost(k) + 1, 0);
            } else if (t[0] === -1) cost += 2 + Math.max(0, integer(t[1]) - 1);
            else if (t[0] === -2) cost += literal(t[2]).length;
            else if (t[0] === -3) cost += 1;
            else fail('page token');
            if (cost > page.decoded_upper_bound) fail('page decoded bound');
          }
        if (Math.max(1, cost) !== page.decoded_upper_bound) fail('page decoded bound');
        if (!memo) tokenPage = { path: page.part.path, data: freeze(data), cost };
        for (
          let i = Math.max(0, first - page.first_token);
          i < Math.min(data.length, end - page.first_token);
          i++
        )
          yield data[i];
      }
    }
    async function* streamRoot(name, options = {}) {
      const [strings, shapes] = await getTables(),
        r = await root(name),
        hash = createHash();
      let size = 0;
      yield* streamTokens(tokens(name, 0, null, options), strings, shapes, {
        ...options,
        observer: (chunk) => {
          hash.update(chunk);
          size += encoder.encode(chunk).length;
          options.observer?.(chunk);
        },
        root: name,
        aliases: (n) => tokens(n),
      });
      if (size !== r.logical.bytes || hash.digest() !== r.logical.sha256)
        fail('root logical fingerprint');
    }
    async function materializeRange(input, options = {}) {
      const r = range(input),
        max = Math.min(integer(options.max_bytes ?? 128000000), 128000000);
      if (r.logical_bytes > max) fail('selected byte budget');
      let canonicalBytes = 0;
      const [strings, shapes] = await getTables(),
        hash = createHash(),
        text = await decodeTokens(
          tokens(r.root, r.first_token, r.end_token, options),
          strings,
          shapes,
          {
            ...options,
            max_bytes: max,
            root: r.root,
            path: options.path,
            observer: (chunk) => {
              hash.update(chunk);
              canonicalBytes += encoder.encode(chunk).length;
            },
            aliases: (n) => tokens(n),
          },
        );
      if (canonicalBytes !== r.logical_bytes || hash.digest() !== r.logical_sha256)
        fail('range logical fingerprint');
      return json.parseStrict(text);
    }
    async function materializeRoot(name, options = {}) {
      const r = await root(name);
      return materializeRange(
        {
          root: name,
          first_token: 0,
          end_token: r.token_count,
          logical_bytes: r.logical.bytes,
          logical_sha256: r.logical.sha256,
        },
        options,
      );
    }
    const rangeMaps = new Map();
    async function findRange(name, path) {
      if (!rangeMaps.has(name))
        rangeMaps.set(
          name,
          (async () => {
            const r = await root(name),
              map = new Map();
            let size = 0;
            for (const d of r.ranges) {
              for (const entry of await read(d, 'ranges')) {
                const key = JSON.stringify(entry.path);
                size += encoder.encode(JSON.stringify(entry)).length;
                if (size > 128000000) fail('range metadata byte budget');
                range(entry.range);
                if (entry.range.root !== name || map.has(key)) fail('range location');
                map.set(key, entry.range);
              }
            }
            return map;
          })(),
        );
      const found = (await rangeMaps.get(name)).get(JSON.stringify(path));
      if (!found) fail('missing range');
      return found;
    }
    async function field(name, path) {
      return materializeRange(await findRange(name, path), { path });
    }
    let routesPromise;
    async function claimRoutes() {
      if (!routesPromise)
        routesPromise = (async () => {
          const [strings] = await getTables(),
            rows = [],
            seen = new Set();
          let previous = null,
            sizeUsed = 0;
          for (const d of catalog.routes.claims) {
            const data = await read(d, 'claim_routes');
            let start = integer(data.base),
              end = integer(data.final_end, 1);
            if (end <= start || (previous !== null && previous !== start)) fail('route contiguity');
            const local = [];
            for (let i = 0; i < data.rows.length; i++) {
              const [atom, delta, size] = data.rows[i];
              integer(atom);
              integer(delta);
              integer(size, 1);
              if (atom >= strings.length || (i === 0 ? delta !== 0 : delta === 0))
                fail('route row');
              start += delta;
              if (start >= end || seen.has(strings[atom])) fail('route overlap or identity');
              seen.add(strings[atom]);
              sizeUsed += strings[atom].length + 64;
              if (sizeUsed > 128000000) fail('route metadata byte budget');
              local.push({ id: strings[atom], first: start, size });
            }
            for (let i = 0; i < local.length; i++)
              rows.push({ ...local[i], end: local[i + 1]?.first ?? end });
            previous = end;
          }
          const bound = await findRange('switching-evidence.json', ['claims']);
          const head = tokens(bound.root, bound.first_token, bound.first_token + 1)[
            Symbol.asyncIterator
          ]();
          const header = (await head.next()).value;
          await head.return?.();
          if (
            !Array.isArray(header) ||
            header[0] !== -1 ||
            header[1] !== rows.length ||
            (rows.length &&
              (rows[0].first !== bound.first_token + 1 || previous !== bound.end_token)) ||
            (!rows.length && bound.end_token !== bound.first_token + 1)
          )
            fail('incomplete claim route membership');
          return rows;
        })();
      return routesPromise;
    }
    async function claimAt(route, options = {}) {
      if (route.size > 128000000) fail('claim byte budget');
      const [strings, shapes] = await getTables();
      const text = await decodeTokens(
        tokens('switching-evidence.json', route.first, route.end, options),
        strings,
        shapes,
        { max_bytes: 128000000, ...options },
      );
      if (encoder.encode(text).length !== route.size) fail('claim size');
      const value = json.parseStrict(text);
      window.InfrastructureSwitchingContracts.validate(
        'switching-evidence-v1.json',
        value,
        '/$defs/claim',
      );
      if (value.claim_id !== route.id) fail('claim identity');
      return value;
    }
    async function switchingClaims(ids) {
      if (
        !Array.isArray(ids) ||
        ids.some((id) => typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id))
      )
        fail('claim ids');
      const byId = new Map((await claimRoutes()).map((r) => [r.id, r]));
      const result = [];
      let size = 0;
      for (const id of new Set(ids)) {
        if (!byId.has(id)) fail('missing claim');
        size += byId.get(id).size;
        if (size > 128000000) fail('selected byte budget');
        result.push(await claimAt(byId.get(id)));
      }
      return result;
    }
    async function* arrayItems(r) {
      range(r);
      const iterator = tokens(r.root, r.first_token, r.end_token)[Symbol.asyncIterator](),
        first = await iterator.next();
      if (
        first.done ||
        !Array.isArray(first.value) ||
        first.value.length !== 2 ||
        first.value[0] !== -1
      )
        fail('array range');
      const count = integer(first.value[1]),
        [strings, shapes] = await getTables(),
        hash = createHash();
      hash.update('[');
      let total = 2,
        deadline = Date.now() + 300000;
      for (let index = 0; index < count; index++) {
        async function* one() {
          let pending = 1;
          while (pending) {
            const entry = await iterator.next();
            if (entry.done) fail('truncated array');
            const t = entry.value;
            pending--;
            if (Array.isArray(t) && t.length === 1) {
              const shape = shapes[integer(t[0])];
              if (!shape) fail('shape');
              pending += shape.length;
            } else if (Array.isArray(t) && t[0] === -1) pending += integer(t[1]);
            yield t;
          }
        }
        if (index) hash.update(',');
        const text = await decodeTokens(one(), strings, shapes, {
          max_bytes: 128000000,
          deadline,
          observer: (chunk) => hash.update(chunk),
        });
        total += encoder.encode(text).length + (index ? 1 : 0);
        if (total > 1000000000) fail('array stream budget');
        yield json.parseStrict(text);
      }
      hash.update(']');
      if (
        !(await iterator.next()).done ||
        total !== r.logical_bytes ||
        hash.digest() !== r.logical_sha256
      )
        fail('array range boundary or fingerprint');
    }
    async function rangePage(r, offset, limit, predicate = () => true) {
      let total = 0;
      const items = [];
      for await (const item of arrayItems(r)) {
        if (!predicate(item)) continue;
        if (total >= offset && items.length < limit) items.push(item);
        total++;
      }
      return { items, total };
    }
    const accepted = new WeakSet();
    async function switchingOverview(evaluatedAt = new Date().toISOString()) {
      const overview = await read(catalog.switching.overview, 'overview'),
        kev = await materializeRange(catalog.switching.kev, { path: ['inputs', 'kev'] });
      const value = json.clone(overview);
      for (const row of value.rows) {
        const k = window.InfrastructureKev.selectReport(kev, row.affected_cve_ids, { evaluatedAt });
        row.kev = {
          availability: k.source.availability,
          listed_cve_ids: row.affected_cve_ids.filter(
            (c) => k.selection.membership[c] === 'listed',
          ),
          unknown_cve_ids: row.affected_cve_ids.filter(
            (c) => k.selection.membership[c] === 'unknown',
          ),
          denominator: row.affected_cve_ids.length,
        };
        row.kev.listed_count = row.kev.listed_cve_ids.length;
        row.kev.unknown_count = row.kev.unknown_cve_ids.length;
      }
      value.evaluated_at = evaluatedAt;
      window.InfrastructureSwitchingContracts.validate('switching-overview-v2.json', value);
      freeze(value);
      accepted.add(value);
      return value;
    }
    async function switchingSelection(options = {}, evaluatedAt = new Date().toISOString()) {
      const overview = await switchingOverview(evaluatedAt);
      const evidence = {};
      for (const key of ['publication', 'generated_at', 'definition_sha256', 'coverage', 'issues'])
        evidence[key] = await field('switching-evidence.json', [key]);
      const kev = await materializeRange(catalog.switching.kev, { path: ['inputs', 'kev'] });
      async function* claims() {
        let size = 2;
        const deadline = Date.now() + 300000;
        for (const route of await claimRoutes()) {
          size += route.size + 1;
          if (size > 1000000000) fail('claim stream byte budget');
          yield await claimAt(route, { deadline });
        }
      }
      const result = await window.InfrastructureSwitching.selectClaims(
        overview,
        evidence,
        kev,
        claims(),
        { ...options, evaluated_at: evaluatedAt },
      );
      freeze(result);
      accepted.add(result);
      return result;
    }
    async function switchingDetails(selection, { kind, row_id = null, cursor = null, limit = 25 }) {
      if (!accepted.has(selection) || selection.publication.id !== identity.publication.id)
        fail('unaccepted detail generation');
      integer(limit, 1);
      if (limit > 25) fail('detail limit');
      const binding = JSON.stringify([identity, selection.selection, kind, row_id]);
      let offset = 0;
      if (cursor !== null) {
        let parsed;
        try {
          parsed = JSON.parse(cursor);
        } catch {
          fail('detail cursor');
        }
        if (parsed.binding !== binding) fail('detail cursor generation');
        offset = integer(parsed.offset);
      }
      if (kind === 'diagnostics' || (kind === 'sources' && !selection.sources)) {
        const page = await rangePage(
          kind === 'diagnostics' ? catalog.switching.diagnostics : selection.detail_ranges.sources,
          offset,
          limit,
          kind === 'diagnostics'
            ? (s) => selection.selection.effective_vendors.includes(s.vendor)
            : () => true,
        );
        if (offset > page.total) fail('detail offset');
        const next = offset + page.items.length;
        return {
          ...page,
          next_cursor: next < page.total ? JSON.stringify({ binding, offset: next }) : null,
        };
      }
      async function* rowArray(row, key) {
        if (row[key]) yield* row[key];
        else yield* arrayItems(row.detail_ranges[key]);
      }
      async function* values() {
        if (kind === 'sources') yield* selection.sources;
        else if (kind === 'claims') {
          const seen = new Set();
          let size = 0;
          for (const row of selection.rows) {
            for await (const id of rowArray(row, 'claim_ids')) {
              if (!seen.has(id)) {
                size += id.length + 3;
                if (size > 128000000) fail('detail membership budget');
                seen.add(id);
                yield id;
              }
            }
            for await (const event of rowArray(row, 'events'))
              for (const id of event.claim_ids) {
                if (!seen.has(id)) {
                  size += id.length + 3;
                  if (size > 128000000) fail('detail membership budget');
                  seen.add(id);
                  yield id;
                }
              }
          }
        } else if (kind === 'status') {
          const row = selection.rows.find((r) => r.row_id === row_id);
          if (!row) fail('detail row');
          for (const value of row.status_buckets) yield { status_bucket: value };
          for await (const value of rowArray(row, 'events')) yield { event: value };
          yield { issues: row.issues };
        } else fail('detail kind');
      }
      const items = [];
      let total = 0;
      for await (const value of values()) {
        if (total >= offset && items.length < limit) items.push(value);
        total++;
      }
      if (offset > total) fail('detail offset');
      const next = offset + items.length;
      return {
        items: kind === 'claims' ? await switchingClaims(items) : items,
        next_cursor: next < total ? JSON.stringify({ binding, offset: next }) : null,
        total,
      };
    }
    async function runtimeSnapshot({ cohort = null, fields = null } = {}) {
      if (cohort !== null) {
        if (!limits.cohortReader) fail('cohort runtime requires static delivery');
        return limits.cohortReader({ cohort, fields });
      }
      if (fields) {
        const result = {};
        for (const key of fields) {
          literal(key);
          Object.defineProperty(result, key, {
            value: await field('runtime-snapshot', [key]),
            enumerable: true,
          });
        }
        return result;
      }
      return materializeRoot('runtime-snapshot');
    }
    return {
      metadata: () => json.clone(catalog),
      streamRoot,
      materializeRange,
      materializeRoot,
      runtimeSnapshot,
      switchingOverview,
      switchingSelection,
      switchingClaims,
      switchingDetails,
      findRange,
      read,
      root,
      tokens,
      getTables,
      cacheBytes: () => bytes,
    };
  }
  window.InfrastructurePublicationV2 = { open, streamTokens, decodeTokens, descriptor, range };
})();
