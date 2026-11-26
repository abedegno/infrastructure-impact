/* Bounded reconstruction of the complete compiled switching analysis. */
(() => {
  const J = window.InfrastructureJSON,
    C = window.InfrastructureSwitchingContracts,
    A = window.InfrastructureSwitchingAnalysis,
    S = window.InfrastructureSwitching,
    encoder = new TextEncoder(),
    ROOT = 'switching-analysis-packed.json',
    MAX = 128000000,
    CHUNK = 65536,
    digest = /^[a-f0-9]{64}$/,
    unicode = /[\uD800-\uDFFF]/u,
    nonASCII = /[^\x00-\x7f]/,
    tableNames = ['claims', 'members', 'requirements'],
    defs = C.policy.schemas['switching-analysis-v1.json'].$defs,
    shapes = {
      claims: defs.compiled.properties.claims.additionalProperties,
      members: defs.compact.properties.members.additionalProperties,
      requirements: defs.compact.properties.requirements.items,
    },
    allowedKeys = new Set(Object.values(shapes).flatMap((shape) => Object.keys(shape.properties))),
    fields = [
      'schema_version',
      'representation',
      'publication',
      'generated_at',
      'definition_sha256',
      'observation_end',
      'source_content_sha256',
      'source_logical_bytes',
      'skeleton_json',
      'layouts',
      'values_json',
      'tables',
      'counts',
      'content_sha256',
    ];
  const fail = (reason) => {
    throw Error('Packed analysis: ' + reason);
  };
  function integer(n, min = 0) {
    if (!Number.isSafeInteger(n) || n < min) fail('unsafe integer');
    return n;
  }
  function at(n, length) {
    const index = integer(n);
    if (index >= length) fail('index out of range');
    return index;
  }
  const isDigest = (v) => typeof v === 'string' && v.length === 64 && digest.test(v);
  const isObject = (v) => v && typeof v === 'object' && !Array.isArray(v);
  const closed = (v, keys) =>
    isObject(v) &&
    Object.keys(v).length === keys.length &&
    keys.every((key) => Object.hasOwn(v, key));

  const arrayPrototypes = new WeakSet([Array.prototype]);
  function isArrayPrototype(proto) {
    if (!proto) return false;
    if (arrayPrototypes.has(proto)) return true;
    const ctor = Object.getOwnPropertyDescriptor(proto, 'constructor')?.value;
    if (
      typeof ctor !== 'function' ||
      Object.getOwnPropertyDescriptor(ctor, 'prototype')?.value !== proto ||
      Function.prototype.toString.call(ctor) !== 'function Array() { [native code] }'
    )
      return false;
    arrayPrototypes.add(proto);
    return true;
  }

  // Public preparation accepts a transferred JSON tree. Inspect descriptors
  // before reading values so a getter cannot run during validation or hashing.
  function freezeOwned(value, seen = new WeakSet(), ancestors = new WeakSet(), depth = 0) {
    if (depth > 64) fail('expected owned JSON data');
    if (typeof value === 'string') {
      if (unicode.test(value)) fail('invalid Unicode');
      return;
    }
    if (value === null || typeof value === 'boolean') return;
    if (typeof value === 'number') {
      integer(value);
      return;
    }
    if (typeof value !== 'object' || ancestors.has(value)) fail('expected owned JSON data');
    if (seen.has(value)) return;
    ancestors.add(value);
    const array = Array.isArray(value),
      prototype = Object.getPrototypeOf(value),
      keys = Reflect.ownKeys(value);
    if (
      (!array && prototype !== null && Object.getPrototypeOf(prototype) !== null) ||
      (array &&
        (!isArrayPrototype(prototype) || keys.length - 1 !== value.length || value.length > MAX))
    )
      fail('expected owned JSON data');
    let i = 0;
    for (const key of keys) {
      if (array && key === 'length') continue;
      const property = Object.getOwnPropertyDescriptor(value, key);
      if (
        typeof key !== 'string' ||
        unicode.test(key) ||
        (array && key !== String(i++)) ||
        !property.enumerable ||
        !Object.hasOwn(property, 'value')
      )
        fail('expected owned JSON data');
      freezeOwned(property.value, seen, ancestors, depth + 1);
    }
    Object.freeze(value);
    seen.add(value);
    ancestors.delete(value);
  }
  function nativeFloat(value) {
    if (Object.is(value, -0)) return '-0.0';
    const magnitude = Math.abs(value);
    // Both runtimes pick the shortest binary64 round trip. Native JSON
    // retains integral-float spelling and uses Python's exponent thresholds.
    if (magnitude === 0 || (magnitude >= 0.0001 && magnitude < 1e16))
      return Number.isInteger(value) ? String(value) + '.0' : String(value);
    const [mantissa, exponent] = value.toExponential().split('e'),
      power = Number(exponent);
    return mantissa + 'e' + (power < 0 ? '-' : '+') + String(Math.abs(power)).padStart(2, '0');
  }
  function parseLiteral(chunks, max) {
    if (!Array.isArray(chunks) || !chunks.length) fail('invalid literal chunks');
    const quota = J.budget(max);
    for (let i = 0; i < chunks.length; i++) {
      const text = chunks[i];
      if (typeof text !== 'string' || !text.length || text.length > CHUNK * 2)
        fail('invalid literal chunks');
      // Native chunks are indexed in Unicode code points. Most literals are ASCII.
      let length = text.length;
      if (/[\uD800-\uDBFF]/.test(text)) for (const c of text) if (c.length === 2) length--;
      if (length > CHUNK || (i < chunks.length - 1 && length !== CHUNK))
        fail('invalid literal chunks');
      quota.charge(nonASCII.test(text) ? encoder.encode(text).length : text.length);
    }
    const text = chunks.length === 1 ? chunks[0] : chunks.join(''),
      value = J.parseStrict(text, { compact: true, formatFloat: nativeFloat });
    return { text, value, rawBytes: quota.used, requestedBytes: J.measure(value, null, '', max) };
  }
  function tableSourceBytes(packed, base, pool, rawCosts, requestedCosts, max) {
    const { layouts, tables, counts, source_logical_bytes } = packed;
    if (!Array.isArray(layouts) || !closed(tables, tableNames) || !closed(counts, tableNames))
      fail('invalid layout or table counts');
    const layoutSeen = new Set(),
      layoutCosts = [];
    for (const keys of layouts) {
      if (
        !Array.isArray(keys) ||
        !keys.length ||
        keys.length > allowedKeys.size ||
        keys.some((key) => !allowedKeys.has(key)) ||
        new Set(keys).size !== keys.length
      )
        fail('invalid layout');
      const literal = JSON.stringify(keys);
      if (layoutSeen.has(literal)) fail('duplicate layout');
      layoutSeen.add(literal);
      layoutCosts.push(2 + keys.length - 1 + keys.reduce((n, k) => n + J.stringBytes(k) + 1, 0));
    }

    const raw = J.budget(source_logical_bytes),
      requested = J.budget(max),
      usedLayouts = new Set(),
      usedValues = new Set();
    raw.charge(base.rawBytes - 12); // Three null placeholders.
    requested.charge(base.requestedBytes - 12);
    for (const name of tableNames) {
      const rows = tables[name],
        shape = shapes[name],
        validLayouts = layouts.map(
          (keys) =>
            shape.required.every((k) => keys.includes(k)) &&
            keys.every((k) => Object.hasOwn(shape.properties, k)),
        ),
        keyed = name !== 'requirements',
        prefix = keyed ? 2 : 1,
        keysSeen = new Set();
      if (!Array.isArray(rows) || rows.length !== integer(counts[name])) fail('invalid row counts');
      const tableBytes = 2 + Math.max(0, rows.length - 1);
      raw.charge(tableBytes);
      requested.charge(tableBytes);
      for (const row of rows) {
        if (!Array.isArray(row) || row.length < prefix) fail('invalid row');
        const layout = at(row[prefix - 1], layouts.length);
        if (row.length !== prefix + layouts[layout].length) fail('invalid row length');
        if (!validLayouts[layout]) fail('invalid table layout');
        usedLayouts.add(layout);
        let rawSize = layoutCosts[layout],
          requestedSize = rawSize;
        if (keyed) {
          const index = at(row[0], pool.length),
            key = pool[index];
          if (!isDigest(key)) fail('invalid row key');
          if (keysSeen.has(key)) fail('duplicate row key');
          keysSeen.add(key);
          usedValues.add(index);
          rawSize += rawCosts[index] + 1;
          requestedSize += requestedCosts[index] + 1;
        }
        for (let i = prefix; i < row.length; i++) {
          const index = at(row[i], pool.length);
          usedValues.add(index);
          rawSize += rawCosts[index];
          requestedSize += requestedCosts[index];
        }
        raw.charge(rawSize);
        requested.charge(requestedSize);
      }
    }
    if (raw.used !== raw.max) fail('source byte budget differs');
    if (usedLayouts.size !== layouts.length || usedValues.size !== pool.length)
      fail('pool/layout closure differs');
    return requested.used;
  }
  function expand(packed, skeleton, pool) {
    for (const name of tableNames) {
      const keyed = name !== 'requirements',
        prefix = keyed ? 2 : 1,
        target = keyed ? {} : [];
      for (const row of packed.tables[name]) {
        const layout = packed.layouts[row[prefix - 1]],
          value = {};
        for (let i = 0; i < layout.length; i++) value[layout[i]] = pool[row[prefix + i]];
        if (keyed) target[pool[row[0]]] = value;
        else target.push(value);
      }
      const owner = name === 'claims' ? skeleton : skeleton.requirements;
      owner[name] = target;
    }
  }
  function deferPreparation(input, sourceBytes, max) {
    let select;
    return Object.freeze({
      sourceBytes,
      prepare() {
        if (select) return select;
        const { skeleton, pool, identity } = input,
          report = { ...skeleton, requirements: { ...skeleton.requirements } };
        expand(input, report, pool);
        // Existing preparation freezes the original report before full
        // fingerprint, shape and semantic validation.
        const choose = A.prepare(report, identity);
        select = (study, { max_bytes = max } = {}) => {
          const limit = Math.min(integer(max_bytes, 1), max);
          if (sourceBytes > limit) fail('source byte budget');
          const result = choose(study);
          J.measure(result, null, '', limit);
          return result;
        };
        input = null;
        return select;
      },
    });
  }
  function preflight(packed, identity = packed, { max_bytes = MAX } = {}) {
    const max = Math.min(integer(max_bytes, 1), MAX);
    freezeOwned(packed);
    if (
      !closed(packed, fields) ||
      packed.schema_version !== 1 ||
      packed.representation !== 'packed-analysis' ||
      !isDigest(packed.source_content_sha256)
    )
      fail('invalid envelope');
    if (integer(packed.source_logical_bytes, 1) > max) fail('source byte budget');
    J.measure(packed, null, '', max);
    const { content_sha256, ...body } = packed;
    if (content_sha256 !== C.fingerprint(body)) fail('envelope fingerprint differs');
    C.identity(packed, identity);
    if (
      packed.definition_sha256 !== C.policy.definition_sha256 ||
      packed.observation_end !== S.day(packed.generated_at) ||
      (identity.observation_end !== undefined &&
        packed.observation_end !== identity.observation_end)
    )
      fail('source identity differs');

    const base = parseLiteral(packed.skeleton_json, max),
      skeleton = base.value;
    if (
      !isObject(skeleton) ||
      skeleton.claims !== null ||
      !isObject(skeleton.requirements) ||
      skeleton.requirements.members !== null ||
      skeleton.requirements.requirements !== null
    )
      fail('invalid table placeholders');
    C.identity(skeleton, packed);
    if (
      skeleton.definition_sha256 !== packed.definition_sha256 ||
      skeleton.observation_end !== packed.observation_end
    )
      fail('source identity differs');
    if (skeleton.content_sha256 !== packed.source_content_sha256)
      fail('source fingerprint differs');

    const pool = [],
      seen = new Set(),
      rawCosts = [],
      requestedCosts = [];
    if (!Array.isArray(packed.values_json)) fail('invalid value pool');
    for (const chunks of packed.values_json) {
      const { text, value, rawBytes, requestedBytes } = parseLiteral(chunks, max);
      if (seen.has(text)) fail('duplicate pool value');
      seen.add(text);
      pool.push(value);
      rawCosts.push(rawBytes);
      requestedCosts.push(requestedBytes);
    }
    const requested = tableSourceBytes(packed, base, pool, rawCosts, requestedCosts, max),
      sourceBytes = Math.max(packed.source_logical_bytes, requested);
    return deferPreparation(
      { layouts: packed.layouts, tables: packed.tables, skeleton, pool, identity },
      sourceBytes,
      max,
    );
  }
  function prepare(packed, identity, options) {
    return preflight(packed, identity, options).prepare();
  }
  window.InfrastructureAnalysisPacking = { ROOT, prepare, preflight };
})();
