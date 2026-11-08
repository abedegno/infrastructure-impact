/* Exact JSON integers without reviver context, rawJSON, dependencies or global patches. */
(() => {
  function parse(text, strict = false, transport = false) {
    let i = 0;
    const fail = () => {
      throw Error('Invalid lossless JSON');
    };
    const space = () => {
      while (/[\x20\t\r\n]/.test(text[i] ?? '') && i < text.length) i++;
    };
    function value(key = '', depth = 0, path = []) {
      if (strict && depth > 64) fail();
      space();
      const start = i,
        ch = text[i];
      if (ch === '"') {
        i++;
        while (i < text.length) {
          if (text[i++] === '"') {
            const result = JSON.parse(text.slice(start, i));
            if (strict && /[\uD800-\uDFFF]/u.test(result)) fail();
            return result;
          }
          if (text[i - 1] === '\\') i++;
        }
        fail();
      }
      if (ch === '{' || ch === '[') {
        const object = ch === '{',
          result = object ? {} : [];
        i++;
        space();
        if (text[i] === (object ? '}' : ']')) {
          i++;
          return result;
        }
        while (i < text.length) {
          let name;
          if (object) {
            space();
            if (text[i] !== '"') fail();
            name = value('', depth + 1, path);
            if (strict && Object.hasOwn(result, name)) fail();
            space();
            if (text[i++] !== ':') fail();
          }
          const v = value(
            object ? name : '',
            depth + 1,
            typeof transport === 'function' ? [...path, object ? name : result.length] : path,
          );
          if (object)
            Object.defineProperty(result, name, {
              value: v,
              enumerable: true,
              writable: true,
              configurable: true,
            });
          else result.push(v);
          space();
          const separator = text[i++];
          if (separator === (object ? '}' : ']')) return result;
          if (separator !== ',') fail();
        }
        fail();
      }
      for (const [token, v] of [
        ['true', true],
        ['false', false],
        ['null', null],
      ])
        if (text.startsWith(token, i)) {
          i += token.length;
          return v;
        }
      const match = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i));
      if (!match || match.index !== 0) fail();
      const token = match[0];
      i += token.length;
      if (
        (transport === true || (typeof transport === 'function' && transport(path))) &&
        /[.eE]/.test(token)
      )
        throw Error('Non-integer transport number lexeme');
      if (['revision_id', 'evidence_id'].includes(key) && /[.eE]/.test(token))
        throw Error('Non-integer identity token');
      const n = Number(token);
      if (
        (transport === true || (typeof transport === 'function' && transport(path))) &&
        !Number.isSafeInteger(n)
      )
        throw Error('Unsafe transport integer lexeme');
      if (!/[.eE]/.test(token) && !Number.isSafeInteger(n)) {
        if (typeof BigInt !== 'function') throw Error('Exact integer identity unsupported');
        return BigInt(token);
      }
      if (!Number.isFinite(n)) fail();
      return n;
    }
    const result = value();
    space();
    if (i !== text.length) fail();
    return result;
  }
  function stringify(value, replacer = null, indent = '') {
    const gap =
      typeof indent === 'number' ? ' '.repeat(Math.min(10, indent)) : String(indent).slice(0, 10);
    const seen = new Set();
    function encode(v, key, depth) {
      if (typeof replacer === 'function') v = replacer(key, v);
      if (typeof v === 'bigint') return v.toString();
      if (v === null || typeof v !== 'object') return JSON.stringify(v);
      if (seen.has(v)) throw TypeError('Cyclic JSON');
      seen.add(v);
      const array = Array.isArray(v),
        entries = [];
      for (const k of array ? v.keys() : Object.keys(v)) {
        const item = encode(v[k], String(k), depth + 1);
        if (item !== undefined || array)
          entries.push((array ? '' : JSON.stringify(k) + (gap ? ': ' : ':')) + (item ?? 'null'));
      }
      seen.delete(v);
      const [open, close] = array ? ['[', ']'] : ['{', '}'];
      return (
        open +
        (entries.length && gap ? '\n' + gap.repeat(depth + 1) : '') +
        entries.join(gap ? ',\n' + gap.repeat(depth + 1) : ',') +
        (entries.length && gap ? '\n' + gap.repeat(depth) : '') +
        close
      );
    }
    return encode(value, '', 0);
  }
  // Count the exact UTF-8 representation without allocating quoted strings,
  // child arrays, or the serialized document. Bounds are charged incrementally.
  function stringBytes(value) {
    let size = 2;
    for (const c of value) {
      const n = c.codePointAt(0);
      size +=
        c === '"' || c === '\\' || '\b\f\n\r\t'.includes(c)
          ? 2
          : n < 32 || (n >= 0xd800 && n <= 0xdfff)
            ? 6
            : n < 128
              ? 1
              : n < 2048
                ? 2
                : n < 65536
                  ? 3
                  : 4;
    }
    return size;
  }
  function budget(maxBytes = 128000000) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > 128000000)
      throw Error('Invalid JSON byte budget');
    return {
      used: 0,
      max: maxBytes,
      get remaining() {
        return this.max - this.used;
      },
      charge(size) {
        if (!Number.isSafeInteger(size) || size < 0 || size > this.remaining)
          throw Error('JSON byte budget exceeded');
        this.used += size;
        return size;
      },
    };
  }
  function measure(value, replacer = null, indent = '', maxBytes = 128000000) {
    if (replacer !== null) throw Error('Bounded JSON replacer unsupported');
    const quota = budget(maxBytes),
      gap =
        typeof indent === 'number' ? ' '.repeat(Math.min(10, indent)) : String(indent).slice(0, 10),
      ancestors = new Set();
    let gapBytes = 0;
    for (const c of gap) {
      const n = c.codePointAt(0);
      gapBytes += n < 128 ? 1 : n < 2048 ? 2 : n < 65536 ? 3 : 4;
    }
    function visit(v, depth, array = false) {
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol') {
        if (array) quota.charge(4);
        return;
      }
      if (typeof v === 'string') {
        quota.charge(stringBytes(v));
        return;
      }
      if (typeof v === 'bigint') {
        quota.charge(v.toString().length);
        return;
      }
      if (v === null || typeof v !== 'object') {
        quota.charge(JSON.stringify(v).length);
        return;
      }
      if (ancestors.has(v)) throw TypeError('Cyclic JSON');
      ancestors.add(v);
      quota.charge(2);
      const list = Array.isArray(v);
      let count = 0;
      for (const key of list ? v.keys() : Object.keys(v)) {
        const child = v[key];
        if (
          !list &&
          (child === undefined || typeof child === 'function' || typeof child === 'symbol')
        )
          continue;
        if (count++) quota.charge(1);
        if (gap) quota.charge(1 + (depth + 1) * gapBytes);
        if (!list) quota.charge(stringBytes(key) + 1 + (gap ? 1 : 0));
        visit(child, depth + 1, list);
      }
      if (count && gap) quota.charge(1 + depth * gapBytes);
      ancestors.delete(v);
    }
    visit(value, 0);
    return quota.used;
  }
  function stringifyBounded(value, replacer = null, indent = '', maxBytes = 128000000) {
    measure(value, replacer, indent, maxBytes);
    return stringify(value, replacer, indent);
  }
  function requestPool() {
    const waiting = [];
    let active = 0;
    return {
      acquire(signal) {
        if (signal?.aborted) return Promise.reject(Error('Publication v2: cancelled'));
        if (active < 6) {
          active++;
          return Promise.resolve();
        }
        return new Promise((resolve, reject) => {
          const entry = {
            resolve: () => {
              signal?.removeEventListener('abort', abort);
              resolve();
            },
          };
          const abort = () => {
            const index = waiting.indexOf(entry);
            if (index >= 0) waiting.splice(index, 1);
            reject(Error('Publication v2: cancelled'));
          };
          waiting.push(entry);
          signal?.addEventListener('abort', abort, { once: true });
        });
      },
      release() {
        const next = waiting.shift();
        if (next) next.resolve();
        else active--;
      },
    };
  }
  window.InfrastructureJSON = {
    parse,
    measure,
    budget,
    stringBytes,
    stringifyBounded,
    requestPool,
    parseStrict: (text, options = {}) => parse(text, true, options.transport),
    stringify,
    clone: (value) => parse(stringify(value)),
  };
})();
