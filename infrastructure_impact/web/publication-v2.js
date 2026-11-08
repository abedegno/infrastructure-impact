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
  const ownedTables = new WeakMap(),
    ownedStates = new WeakSet(),
    ownedValues = new WeakSet();
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
  let operationId = 0;
  function operation(options = {}) {
    if (options.operation) return options.operation;
    const controller = new AbortController(),
      deadline = Math.min(options.deadline ?? Infinity, Date.now() + 300000);
    const abort = () => controller.abort();
    options.signal?.addEventListener('abort', abort, { once: true });
    if (options.signal?.aborted) abort();
    let rejectAbort;
    const interrupted = new Promise((_, reject) => {
      rejectAbort = reject;
    });
    const onAbort = () =>
      rejectAbort(
        Error(
          Date.now() >= deadline ? 'Publication v2: stream deadline' : 'Publication v2: cancelled',
        ),
      );
    controller.signal.addEventListener('abort', onAbort, { once: true });
    // Attach a handler immediately: abort may happen between awaited reads.
    interrupted.catch(() => {});
    const timer = setTimeout(abort, Math.max(0, deadline - Date.now()));
    return {
      id: ++operationId,
      signal: controller.signal,
      deadline,
      run(promise) {
        if (Date.now() >= deadline) {
          abort();
          return Promise.reject(Error('Publication v2: stream deadline'));
        }
        if (controller.signal.aborted) return Promise.reject(Error('Publication v2: cancelled'));
        return Promise.race([promise, interrupted]).then((value) => {
          if (Date.now() >= deadline) {
            abort();
            throw Error('Publication v2: stream deadline');
          }
          if (controller.signal.aborted) throw Error('Publication v2: cancelled');
          return value;
        });
      },
      close() {
        abort();
        clearTimeout(timer);
        options.signal?.removeEventListener('abort', abort);
        controller.signal.removeEventListener('abort', onAbort);
      },
    };
  }
  async function scoped(options, fn) {
    const op = operation(options);
    try {
      const result = await fn({
        ...options,
        operation: op,
        signal: op.signal,
        deadline: op.deadline,
      });
      return await op.run(Promise.resolve(result));
    } finally {
      if (!options?.operation) op.close();
    }
  }
  async function* streamTokens(tokens, strings, shapes, options = {}) {
    const ownsOperation = !options.operation,
      op = operation(options);
    options = { ...options, operation: op, signal: op.signal, deadline: op.deadline };
    let iterator,
      completed = false;
    try {
      iterator = tokens?.[Symbol.asyncIterator]?.() || tokens?.[Symbol.iterator]?.();
      if (!iterator) fail('invalid token iterator');
      if (ownedTables.get(strings) !== shapes) tables(strings, shapes);
      const state = (ownedStates.has(options.state) ? options.state : null) || {
        used: 0,
        max: Math.min(integer(options.max_bytes ?? 1000000000), 1000000000),
        deadline: op.deadline,
        canonicalUsed: 0,
        canonicalMax: Math.min(integer(options.canonical_bytes ?? 1000000000), 1000000000),
      };
      ownedStates.add(state);
      if (options.valueState && !ownedValues.has(options.valueState)) options.valueState = null;
      const ascii = options.serialization === 'ascii';
      if (options.serialization && !['logical', 'ascii'].includes(options.serialization))
        fail('serialization');
      function charge(size, canonical = size) {
        if (options.signal?.aborted) fail('cancelled');
        if (Date.now() > state.deadline) fail('stream deadline');
        if (size > state.max - state.used) fail('decoded byte budget');
        if (canonical > (state.canonicalMax ?? 1000000000) - (state.canonicalUsed ?? 0))
          fail('declared canonical byte budget');
        if (options.valueState && size > options.valueState.max - options.valueState.used)
          fail('materialized value byte budget');
        state.used += size;
        state.canonicalUsed = (state.canonicalUsed ?? 0) + canonical;
        if (options.valueState) options.valueState.used += size;
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
        charge(Math.max(stringCost(s), stringCost(s, ascii)), stringCost(s));
        const raw = quote(s, ascii);
        options.observer?.(quote(s, false));
        return raw;
      }
      async function nextToken() {
        return op.run(iterator.next());
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
      completed = true;
    } finally {
      if (ownsOperation || !completed) op.close();
      // Abort owned I/O first, then request cursor finalization. A hostile caller
      // iterator cannot keep cleanup blocked after ignoring cancellation.
      if (iterator?.return)
        await Promise.race([
          Promise.resolve(iterator.return()).catch(() => {}),
          new Promise((resolve) => setTimeout(resolve, 0)),
        ]);
    }
  }
  async function decodeTokens(tokens, strings, shapes, options = {}) {
    const valueState = ownedValues.has(options.valueState)
      ? options.valueState
      : {
          used: 0,
          max: Math.min(
            integer(options.value_max_bytes ?? options.max_bytes ?? 128000000),
            128000000,
          ),
        };
    ownedValues.add(valueState);
    const pieces = [];
    for await (const chunk of streamTokens(tokens, strings, shapes, {
      max_bytes: 128000000,
      ...options,
      valueState,
    }))
      pieces.push(chunk);
    return pieces.join('');
  }
  function descriptor(d, compressed = false) {
    if (
      !d ||
      Object.keys(d).sort().join(',') !== 'bytes,path,sha256' ||
      !(compressed ? /^data\/v2\/[a-f0-9]{64}\.json\.gz$/ : /^data\/v2\/[a-f0-9]{64}\.json$/).test(
        d.path,
      ) ||
      d.path !== `data/v2/${d.sha256}.json${compressed ? '.gz' : ''}` ||
      integer(d.bytes, 1) > 8000000
    )
      fail('descriptor');
    return d;
  }
  function tableTransports(catalog) {
    if (!Object.hasOwn(catalog, 'table_transports')) return {};
    const transports = catalog.table_transports;
    if (!transports || typeof transports !== 'object' || Array.isArray(transports))
      fail('table transports');
    const paths = new Set(
        [...catalog.strings, ...catalog.shapes].map((entry) => descriptor(entry.part).path),
      ),
      compressedPaths = new Set();
    for (const [path, transport] of Object.entries(transports)) {
      if (!paths.has(path)) fail('unknown table transport');
      descriptor(transport, true);
      if (compressedPaths.has(transport.path)) fail('duplicate table transport');
      compressedPaths.add(transport.path);
    }
    return transports;
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
    const transports = tableTransports(catalog),
      cache = new Map(),
      pending = new Map(),
      pool = json.requestPool();
    let bytes = 0;
    const maxCache = Math.min(integer(limits.cache_bytes ?? 16000000), 16000000);
    async function raw(d, options = {}) {
      const op = options.operation,
        signal = op?.signal ?? options.signal;
      d = Object.freeze({ ...descriptor(d) });
      const encoded =
        typeof DecompressionStream === 'function' && Object.hasOwn(transports, d.path)
          ? transports[d.path]
          : d;
      if (cache.has(d.path)) {
        const value = cache.get(d.path);
        cache.delete(d.path);
        cache.set(d.path, value);
        return value;
      }
      const pendingKey = String(op?.id ?? '') + ':' + d.path;
      if (pending.has(pendingKey)) return pending.get(pendingKey);
      const promise = (async () => {
        await pool.acquire(signal);
        try {
          await limits.requestSlots?.acquire(signal);
        } catch (error) {
          pool.release();
          throw error;
        }
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
          const wait = (promise) => {
            const bounded = Promise.race([promise, expired]);
            return op ? op.run(bounded) : bounded;
          };
          async function readBytes(body, bound) {
            const reader = body.getReader(),
              pieces = [];
            let size = 0;
            try {
              for (;;) {
                const part = await wait(reader.read());
                if (part.done) break;
                // Retain at most the declared bytes; the first excess byte is
                // sufficient to reject, including a single oversized chunk.
                if (part.value.length > bound - size) fail('part size');
                size += part.value.length;
                pieces.push(part.value);
              }
              const result = new Uint8Array(size);
              let offset = 0;
              for (const piece of pieces) {
                result.set(piece, offset);
                offset += piece.length;
              }
              return result;
            } finally {
              // Cancellation is advisory: a stalled decoder/body must not
              // retain the request slot or poison the pending metadata cache.
              try {
                Promise.resolve(reader.cancel()).catch(() => {});
              } catch {}
              try {
                reader.releaseLock();
              } catch {}
            }
          }
          async function verified(value, expected) {
            if (value.length !== expected.bytes || (await wait(digest(value))) !== expected.sha256)
              fail('part fingerprint');
            return value;
          }
          const response = await wait(fetchPart(encoded.path, { signal: controller.signal }));
          if (!response.ok) fail('part unavailable');
          let value = await verified(
            response.body?.getReader
              ? await readBytes(response.body, encoded.bytes)
              : new Uint8Array(await wait(response.arrayBuffer())),
            encoded,
          );
          if (encoded !== d) {
            const decoded = new Response(value).body.pipeThrough(new DecompressionStream('gzip'));
            value = await verified(await readBytes(decoded, d.bytes), d);
          }
          if (value.length <= maxCache) {
            while (bytes + value.length > maxCache) {
              const key = cache.keys().next().value;
              bytes -= cache.get(key).length;
              cache.delete(key);
            }
            if (cache.has(d.path)) bytes -= cache.get(d.path).length;
            cache.set(d.path, value);
            bytes += value.length;
          }
          return value;
        } finally {
          controller.abort();
          clearTimeout(timer);
          signal?.removeEventListener('abort', abort);
          limits.requestSlots?.release();
          pool.release();
        }
      })();
      pending.set(pendingKey, promise);
      try {
        return await promise;
      } finally {
        pending.delete(pendingKey);
      }
    }
    async function read(d, kind, options = {}) {
      if (!options.operation) return scoped(options, (next) => read(d, kind, next));
      const value = json.parseStrict(
        new TextDecoder('utf-8', { fatal: true }).decode(await raw(d, options)),
        { transport: kind === 'overview' ? (path) => path[0] !== 'data' : true },
      );
      window.InfrastructureSwitchingContracts.envelope(value, kind);
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
    async function getTables(options = {}) {
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
              const data = await read(entry.part, kind, options);
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
      try {
        return await tablePromise;
      } catch (error) {
        tablePromise = null;
        throw error;
      }
    }
    const roots = new Map();
    async function root(name, options = {}) {
      if (!Object.hasOwn(catalog.roots, name)) fail('unknown root');
      if (!roots.has(name))
        roots.set(
          name,
          (async () => {
            const data = await read(catalog.roots[name], 'root', options);
            if (data.name !== name) fail('root name');
            let end = 0;
            for (const page of data.pages) {
              if (page.first_token !== end) fail('page contiguity');
              integer(page.decoded_upper_bound, 1);
              end += integer(page.count, 1);
            }
            if (end !== data.token_count) fail('root token count');
            return freeze(data);
          })(),
        );
      try {
        return await roots.get(name);
      } catch (error) {
        roots.delete(name);
        throw error;
      }
    }
    let tokenPage = null; // One verified decoded page, never an unbounded page cache.
    async function* tokens(name, first = 0, end = null, options = {}) {
      const r = await root(name, options);
      end ??= r.token_count;
      integer(first);
      integer(end, 1);
      if (first >= end || end > r.token_count) fail('token range');
      for (const page of r.pages) {
        if (page.first_token >= end || page.first_token + page.count <= first) continue;
        if (page.decoded_upper_bound > Math.min(limits.page_bytes ?? 128000000, 128000000))
          fail('page expansion bound');
        const memo = tokenPage?.path === page.part.path ? tokenPage : null;
        const data = memo?.data ?? (await read(page.part, 'tokens', options));
        if (data.length !== page.count) fail('page count');
        const [strings, shapes] = await getTables(options);
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
      const ownsOperation = !options.operation,
        op = operation(options);
      options = { ...options, operation: op, signal: op.signal, deadline: op.deadline };
      try {
        const [strings, shapes] = await op.run(getTables(options)),
          r = await op.run(root(name, options)),
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
          canonical_bytes: r.logical.bytes,
          aliases: (n) => tokens(n, 0, null, options),
        });
        if (size !== r.logical.bytes || hash.digest() !== r.logical.sha256)
          fail('root logical fingerprint');
      } finally {
        if (ownsOperation) op.close();
      }
    }
    async function materializeRange(input, options = {}) {
      if (!options.operation) return scoped(options, (next) => materializeRange(input, next));
      const r = freeze(json.clone(range(input))),
        max = Math.min(integer(options.max_bytes ?? limits.selected_bytes ?? 128000000), 128000000);
      if (r.logical_bytes > max) fail('selected byte budget');
      let canonicalBytes = 0;
      const [strings, shapes] = await getTables(options),
        hash = createHash(),
        text = await decodeTokens(
          tokens(r.root, r.first_token, r.end_token, options),
          strings,
          shapes,
          {
            ...options,
            max_bytes: max,
            canonical_bytes: r.logical_bytes,
            root: r.root,
            path: options.path,
            observer: (chunk) => {
              hash.update(chunk);
              canonicalBytes += encoder.encode(chunk).length;
            },
            aliases: (n) => tokens(n, 0, null, options),
          },
        );
      if (canonicalBytes !== r.logical_bytes || hash.digest() !== r.logical_sha256)
        fail('range logical fingerprint');
      return json.parseStrict(text);
    }
    async function materializeRoot(name, options = {}) {
      if (!options.operation) return scoped(options, (next) => materializeRoot(name, next));
      const r = await root(name, options);
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
    async function findRange(name, path, options = {}) {
      if (!rangeMaps.has(name))
        rangeMaps.set(
          name,
          (async () => {
            const r = await root(name, options),
              map = new Map();
            let size = 0;
            for (const d of r.ranges) {
              for (const entry of await read(d, 'ranges', options)) {
                size += json.measure(entry, null, '', 128000000 - size);
                const key = json.stringifyBounded(entry.path);
                freeze(entry.range);
                range(entry.range);
                if (entry.range.root !== name || map.has(key)) fail('range location');
                map.set(key, entry.range);
              }
            }
            return map;
          })(),
        );
      let map;
      try {
        map = await rangeMaps.get(name);
      } catch (error) {
        rangeMaps.delete(name);
        throw error;
      }
      const found = map.get(JSON.stringify(path));
      if (!found) fail('missing range');
      return found;
    }
    async function field(name, path, options = {}) {
      return materializeRange(await findRange(name, path, options), { ...options, path });
    }
    let routesPromise;
    async function claimRoutes(options = {}) {
      if (!routesPromise)
        routesPromise = (async () => {
          const [strings] = await getTables(options),
            rows = [],
            seen = new Set();
          let previous = null,
            sizeUsed = 0;
          for (const d of catalog.routes.claims) {
            const data = await read(d, 'claim_routes', options);
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
          const bound = await findRange('switching-evidence.json', ['claims'], options);
          const head = tokens(bound.root, bound.first_token, bound.first_token + 1, options)[
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
      try {
        return await routesPromise;
      } catch (error) {
        routesPromise = null;
        throw error;
      }
    }
    async function claimAt(route, options = {}) {
      if (route.size > 128000000) fail('claim byte budget');
      const [strings, shapes] = await getTables(options);
      const text = await decodeTokens(
        tokens('switching-evidence.json', route.first, route.end, options),
        strings,
        shapes,
        { max_bytes: 128000000, ...options, canonical_bytes: route.size },
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
    async function switchingClaims(ids, options = {}) {
      if (!options.operation) return scoped(options, (next) => switchingClaims(ids, next));
      if (
        !Array.isArray(ids) ||
        ids.some((id) => typeof id !== 'string' || !/^[a-f0-9]{64}$/.test(id))
      )
        fail('claim ids');
      const byId = new Map((await claimRoutes(options)).map((r) => [r.id, r]));
      const result = [],
        quota = options.budget ?? json.budget(selectedMax);
      if (!options.budget) quota.charge(2);
      let size = 0;
      for (const id of new Set(ids)) {
        if (!byId.has(id)) fail('missing claim');
        size += byId.get(id).size;
        if (size > 128000000) fail('selected byte budget');
        quota.charge(byId.get(id).size + (result.length ? 1 : 0));
        result.push(await claimAt(byId.get(id), { ...options, max_bytes: byId.get(id).size }));
      }
      return result;
    }
    async function* arrayItems(r, options = {}) {
      const owns = !options.operation,
        op = operation(options);
      options = { ...options, operation: op, signal: op.signal, deadline: op.deadline };
      let iterator,
        completed = false;
      try {
        range(r);
        iterator = tokens(r.root, r.first_token, r.end_token, options)[Symbol.asyncIterator]();
        const first = await op.run(iterator.next());
        if (
          first.done ||
          !Array.isArray(first.value) ||
          first.value.length !== 2 ||
          first.value[0] !== -1
        )
          fail('array range');
        const count = integer(first.value[1]),
          [strings, shapes] = await op.run(getTables(options)),
          hash = createHash();
        const state = {
          used: 2,
          canonicalUsed: 2,
          max: 1000000000,
          canonicalMax: r.logical_bytes,
          deadline: op.deadline,
        };
        ownedStates.add(state);
        if (r.logical_bytes < 2) fail('declared canonical byte budget');
        hash.update('[');
        for (let index = 0; index < count; index++) {
          if (index) {
            if (state.canonicalUsed >= state.canonicalMax || state.used >= state.max)
              fail('array byte budget');
            state.used++;
            state.canonicalUsed++;
            hash.update(',');
          }
          async function* one() {
            let pending = 1;
            while (pending) {
              const entry = await op.run(iterator.next());
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
          if (options.skipValue?.(index)) {
            // Validate/hash excluded values as bounded streams without creating
            // a JSON string or object under the selected page's allowance.
            const valueState = {
              used: 0,
              max: Math.min(limits.selected_bytes ?? 128000000, 128000000),
            };
            ownedValues.add(valueState);
            for await (const chunk of streamTokens(one(), strings, shapes, {
              ...options,
              state,
              valueState,
              observer: (chunk) => hash.update(chunk),
            })) {
            }
            continue;
          }
          const allowance = Math.min(
            options.valueLimit?.(index) ?? limits.selected_bytes ?? 128000000,
            128000000,
          );
          const text = await decodeTokens(one(), strings, shapes, {
            ...options,
            state,
            value_max_bytes: allowance,
            observer: (chunk) => hash.update(chunk),
          });
          const size = encoder.encode(text).length;
          options.beforeValue?.(size, index);
          yield { value: json.parseStrict(text), bytes: size, index };
        }
        hash.update(']');
        if (
          !(await op.run(iterator.next())).done ||
          state.canonicalUsed !== r.logical_bytes ||
          hash.digest() !== r.logical_sha256
        )
          fail('array range boundary or fingerprint');
        completed = true;
      } finally {
        if (owns || !completed) op.close();
        if (iterator?.return)
          await Promise.race([
            Promise.resolve(iterator.return()).catch(() => {}),
            new Promise((resolve) => setTimeout(resolve, 0)),
          ]);
      }
    }
    const selectedMax = Math.min(integer(limits.selected_bytes ?? 128000000, 1), 128000000);
    function pageBudget(total, binding, offset, limit) {
      const next = Math.min(total, offset + limit),
        next_cursor = next < total ? JSON.stringify({ binding, offset: next }) : null;
      const quota = json.budget(selectedMax);
      quota.charge(json.measure({ items: [], next_cursor, total }));
      return { quota, next_cursor };
    }
    async function indexedRangePage(kind, input, offset, limit, vendors, binding, options) {
      const r = range(input),
        chunks = catalog.switching.detail_indexes[kind];
      let count = 0,
        total = 0;
      const selectedCount = (chunk) =>
        vendors === null
          ? chunk.count
          : Object.entries(chunk.vendors).reduce(
              (n, [vendor, number]) => n + (vendors.has(vendor) ? number : 0),
              0,
            );
      for (const chunk of chunks) {
        if (integer(chunk.first) !== count) fail('detail chunk order/count');
        count += integer(chunk.count, 1);
        const vendorCount = Object.values(chunk.vendors).reduce((n, v) => n + integer(v, 1), 0);
        if (kind === 'diagnostics' ? vendorCount !== chunk.count : vendorCount !== 0)
          fail('detail chunk vendor counts');
        total += selectedCount(chunk);
      }
      const header = tokens(r.root, r.first_token, r.first_token + 1, options)[
        Symbol.asyncIterator
      ]();
      try {
        const first = (await header.next()).value;
        if (!Array.isArray(first) || first.length !== 2 || first[0] !== -1 || first[1] !== count)
          fail('detail index parent count');
      } finally {
        await header.return?.();
      }
      if (offset > total) fail('detail offset');
      const { quota, next_cursor } = pageBudget(total, binding, offset, limit),
        items = [];
      let passed = 0;
      for (const chunk of chunks) {
        const selected = selectedCount(chunk),
          start = passed;
        passed += selected;
        if (!selected || passed <= offset || start >= offset + limit) continue;
        const entries = await read(chunk.part, 'detail_index', options),
          actualVendors = {};
        if (entries.length !== chunk.count) fail('detail chunk count');
        let previous = null;
        for (let i = 0; i < entries.length; i++) {
          const entry = entries[i],
            bound = range(entry.range),
            ordinal = chunk.first + i;
          if (
            entry.ordinal !== ordinal ||
            bound.root !== r.root ||
            bound.first_token <= r.first_token ||
            bound.end_token > r.end_token ||
            (previous !== null && previous !== bound.first_token) ||
            (ordinal === 0 && bound.first_token !== r.first_token + 1) ||
            (ordinal === count - 1 && bound.end_token !== r.end_token)
          )
            fail('detail item routing');
          previous = bound.end_token;
          if (kind === 'diagnostics') {
            if (typeof entry.vendor !== 'string') fail('detail vendor');
            Object.defineProperty(actualVendors, entry.vendor, {
              value:
                (Object.hasOwn(actualVendors, entry.vendor) ? actualVendors[entry.vendor] : 0) + 1,
              enumerable: true,
              configurable: true,
            });
          } else if (Object.hasOwn(entry, 'vendor')) fail('source detail vendor');
        }
        if (
          Object.keys(actualVendors).length !== Object.keys(chunk.vendors).length ||
          Object.entries(actualVendors).some(([vendor, n]) => chunk.vendors[vendor] !== n)
        )
          fail('detail chunk vendor counts');
        let local = start;
        for (const entry of entries) {
          if (vendors !== null && !vendors.has(entry.vendor)) continue;
          const index = local++;
          if (index < offset || index >= offset + limit) continue;
          const value = await materializeRange(entry.range, {
            ...options,
            path:
              kind === 'diagnostics'
                ? ['score_availability', entry.ordinal]
                : ['switching_comparison', 'sources', entry.ordinal],
            max_bytes: Math.max(0, quota.remaining - (items.length ? 1 : 0)),
          });
          if (kind === 'diagnostics' && value.vendor !== entry.vendor)
            fail('detail vendor identity');
          quota.charge(json.measure(value, null, '', quota.remaining) + (items.length ? 1 : 0));
          items.push(value);
        }
      }
      return { items, total, next_cursor };
    }
    async function rangePage(r, offset, limit, predicate, binding, options) {
      let total = 0;
      const positions = new Set();
      for await (const { value, index } of arrayItems(r, options))
        if (predicate(value)) {
          if (total >= offset && positions.size < limit) positions.add(index);
          total++;
        }
      if (offset > total) fail('detail offset');
      const { quota, next_cursor } = pageBudget(total, binding, offset, limit),
        items = [];
      if (positions.size)
        for await (const { value } of arrayItems(r, {
          ...options,
          skipValue: (index) => !positions.has(index),
          valueLimit: () => quota.remaining - (items.length ? 1 : 0),
        })) {
          quota.charge(json.measure(value, null, '', quota.remaining) + (items.length ? 1 : 0));
          items.push(value);
        }
      return { items, total, next_cursor };
    }
    const accepted = new WeakSet();
    async function switchingOverview(evaluatedAt = new Date().toISOString(), options = {}) {
      if (!options.operation)
        return scoped(options, (next) => switchingOverview(evaluatedAt, next));
      const overview = await read(catalog.switching.overview, 'overview', options),
        kev = await materializeRange(catalog.switching.kev, {
          ...options,
          path: ['inputs', 'kev'],
        });
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
    async function publishedSelection(overview, consumption) {
      const { detail_ranges, rows, ...header } = json.clone(overview),
        quota = json.budget(selectedMax),
        result = { ...header, schema_version: 1, representation: 'summary', rows: [], sources: [] };
      quota.charge(json.measure(result, null, '', quota.remaining));
      for (let index = 0; index < rows.length; index++) {
        const { detail_ranges: fields, ...row } = rows[index];
        quota.charge(json.measure(row, null, '', quota.remaining) + 1);
        for (const [key, bound] of Object.entries(fields)) {
          quota.charge(json.stringBytes(key) + 2);
          const value = await materializeRange(bound, {
            ...consumption,
            path: ['switching_comparison', 'rows', index, key],
            max_bytes: quota.remaining,
          });
          quota.charge(json.measure(value, null, '', quota.remaining));
          row[key] = value;
        }
        result.rows.push(row);
      }
      result.sources = await materializeRange(detail_ranges.sources, {
        ...consumption,
        path: ['switching_comparison', 'sources'],
        max_bytes: quota.remaining,
      });
      quota.charge(json.measure(result.sources, null, '', quota.remaining));
      json.measure(result, null, '', selectedMax);
      window.InfrastructureSwitchingContracts.summary(result, overview);
      freeze(result);
      accepted.add(result);
      return result;
    }
    async function switchingSelection(
      options = {},
      evaluatedAt = new Date().toISOString(),
      consumption = {},
    ) {
      if (!consumption.operation)
        return scoped(consumption, (next) => switchingSelection(options, evaluatedAt, next));
      const overview = await switchingOverview(evaluatedAt, consumption);
      // The ordinary default already has publisher-computed rows and details.
      // Reuse them; custom selections still run the complete claim reducer.
      if (
        Object.keys(options).every((key) =>
          ['vendor', 'scope_level', 'window', 'cve_ids'].includes(key),
        ) &&
        options.vendor == null &&
        options.cve_ids == null &&
        (options.scope_level === undefined || options.scope_level === 'os_family') &&
        (options.window === undefined || options.window === 'all')
      )
        return publishedSelection(overview, consumption);
      const evidence = {};
      for (const key of ['publication', 'generated_at', 'definition_sha256', 'coverage', 'issues'])
        evidence[key] = await field('switching-evidence.json', [key], consumption);
      const kev = await materializeRange(catalog.switching.kev, {
        ...consumption,
        path: ['inputs', 'kev'],
      });
      async function* claims() {
        let size = 2;
        const deadline = consumption.deadline;
        for (const route of await claimRoutes(consumption)) {
          size += route.size + 1;
          if (size > 1000000000) fail('claim stream byte budget');
          yield await claimAt(route, { ...consumption, deadline });
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
    const selectionIds = new WeakMap();
    let nextSelectionId = 0;
    async function switchingDetails(selection, request, options = {}) {
      if (!options.operation)
        return scoped(options, (next) => switchingDetails(selection, request, next));
      const { kind, row_id = null, cursor = null, limit = 25 } = request;
      if (!accepted.has(selection) || selection.publication.id !== identity.publication.id)
        fail('unaccepted detail generation');
      integer(limit, 1);
      if (limit > 25) fail('detail limit');
      if (!selectionIds.has(selection)) selectionIds.set(selection, ++nextSelectionId);
      const binding = JSON.stringify([identity, selectionIds.get(selection), kind, row_id]);
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
      if (
        (kind === 'diagnostics' || (kind === 'sources' && !selection.sources)) &&
        catalog.switching.detail_indexes
      )
        return indexedRangePage(
          kind,
          kind === 'diagnostics' ? catalog.switching.diagnostics : selection.detail_ranges.sources,
          offset,
          limit,
          kind === 'diagnostics' ? new Set(selection.selection.effective_vendors) : null,
          binding,
          options,
        );
      if (kind === 'diagnostics' || (kind === 'sources' && !selection.sources))
        return rangePage(
          kind === 'diagnostics' ? catalog.switching.diagnostics : selection.detail_ranges.sources,
          offset,
          limit,
          kind === 'diagnostics'
            ? (s) => selection.selection.effective_vendors.includes(s.vendor)
            : () => true,
          binding,
          options,
        );
      async function* rowArray(row, key, allowance) {
        if (row[key]) yield* row[key];
        else
          for await (const { value } of arrayItems(row.detail_ranges[key], {
            ...options,
            valueLimit: allowance,
          }))
            yield value;
      }
      async function* values(allowance = () => selectedMax) {
        if (kind === 'sources') yield* selection.sources;
        else if (kind === 'claims') {
          const seen = new Set(),
            quota = json.budget(selectedMax);
          for (const row of selection.rows) {
            for await (const id of rowArray(row, 'claim_ids', () => selectedMax)) {
              if (!seen.has(id)) {
                quota.charge(json.stringBytes(id) + 1);
                seen.add(id);
                yield id;
              }
            }
            for await (const event of rowArray(row, 'events', () => selectedMax))
              for (const id of event.claim_ids) {
                if (!seen.has(id)) {
                  quota.charge(json.stringBytes(id) + 1);
                  seen.add(id);
                  yield id;
                }
              }
          }
        } else if (kind === 'status') {
          const row = selection.rows.find((r) => r.row_id === row_id);
          if (!row) fail('detail row');
          for (const value of row.status_buckets) yield { status_bucket: value };
          for await (const value of rowArray(row, 'events', () => Math.max(0, allowance() - 10)))
            yield { event: value };
          yield { issues: row.issues };
        } else fail('detail kind');
      }
      let total = 0;
      for await (const value of values()) total++;
      if (offset > total) fail('detail offset');
      const { quota, next_cursor } = pageBudget(total, binding, offset, limit),
        items = [];
      let index = 0;
      for await (const value of values(() =>
        index >= offset && items.length < limit
          ? quota.remaining - (items.length ? 1 : 0)
          : selectedMax,
      )) {
        if (index++ < offset || items.length >= limit) continue;
        if (kind === 'claims') items.push(value);
        else {
          quota.charge(json.measure(value, null, '', quota.remaining) + (items.length ? 1 : 0));
          items.push(value);
        }
      }
      return {
        items:
          kind === 'claims' ? await switchingClaims(items, { ...options, budget: quota }) : items,
        next_cursor,
        total,
      };
    }
    async function runtimeSnapshot({ cohort = null, fields = null, ...options } = {}) {
      if (cohort !== null && !limits.cohortReader) fail('cohort runtime requires static delivery');
      if (!options.operation)
        return scoped(options, (next) => runtimeSnapshot({ cohort, fields, ...next }));
      const max = Math.min(selectedMax, integer(options.max_bytes ?? selectedMax, 1));
      if (cohort !== null)
        return limits.cohortReader({ cohort, fields, ...options, max_bytes: max });
      if (fields) {
        const result = {},
          quota = json.budget(max);
        quota.charge(2);
        let count = 0;
        for (const key of new Set(fields)) {
          literal(key);
          const bound = await findRange('runtime-snapshot', [key], options);
          quota.charge(json.stringBytes(key) + 1 + (count++ ? 1 : 0) + bound.logical_bytes);
          const value = await materializeRange(bound, {
            ...options,
            path: [key],
            max_bytes: bound.logical_bytes,
          });
          Object.defineProperty(result, key, { value, enumerable: true });
        }
        return result;
      }
      return materializeRoot('runtime-snapshot', { ...options, max_bytes: max });
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
  window.InfrastructurePublicationV2 = {
    open,
    streamTokens,
    decodeTokens,
    descriptor,
    range,
    consume: scoped,
  };
})();
