/* Exact JSON integers without reviver context, rawJSON, dependencies or global patches. */
(() => {
  function parse(text, strict = false) {
    let i = 0;
    const fail = () => {
      throw Error('Invalid lossless JSON');
    };
    const space = () => {
      while (/[\x20\t\r\n]/.test(text[i] ?? '') && i < text.length) i++;
    };
    function value(key = '', depth = 0) {
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
            name = value('', depth + 1);
            if (strict && Object.hasOwn(result, name)) fail();
            space();
            if (text[i++] !== ':') fail();
          }
          const v = value(object ? name : '', depth + 1);
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
      if (['revision_id', 'evidence_id'].includes(key) && /[.eE]/.test(token))
        throw Error('Non-integer identity token');
      const n = Number(token);
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
  window.InfrastructureJSON = {
    parse,
    parseStrict: (text) => parse(text, true),
    stringify,
    clone: (value) => parse(stringify(value)),
  };
})();
