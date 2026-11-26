/* Bounded transport for native selected analysis. Loaded lazily by the v2 reader. */
(() => {
  const J = window.InfrastructureJSON,
    C = window.InfrastructureSwitchingContracts,
    S = window.InfrastructureSwitching,
    D = C.policy.study_definition,
    ROOT = 'switching-analysis-selected.json',
    SLICE = 4000000,
    MAX = 128000000,
    MANIFEST_MAX = 2000000,
    vendors = ['cisco', 'aruba', 'arista'],
    scopes = ['os_family', 'model_qualified'],
    families = Object.fromEntries(D.targets.map(({ vendor, family }) => [vendor, family])),
    eq = (a, b) => C.fingerprint({ value: a }) === C.fingerprint({ value: b }),
    sorted = (a) => [...new Set(a)].sort(),
    fail = (message) => {
      throw Error('Selected analysis: ' + message);
    };

  function ownValue(object, key, required = true) {
    if (!object || typeof object !== 'object') fail('expected owned JSON object');
    const property = Object.getOwnPropertyDescriptor(object, key);
    if (!property && !required) return undefined;
    if (!property || !Object.hasOwn(property, 'value') || !property.enumerable)
      fail('expected owned JSON data without accessors');
    return property.value;
  }
  function snapshot(value, max) {
    // Inspect property descriptors before obtaining values. Precharge the
    // actual JSON cost before copying further, with a fixed depth and no cycles.
    const quota = J.budget(max),
      ancestors = new Set();
    function string(value) {
      if (value.length + 2 > quota.remaining) fail('byte budget');
      if (/[\uD800-\uDFFF]/u.test(value)) fail('invalid owned JSON string');
      quota.charge(J.stringBytes(value));
    }
    function visit(value, depth) {
      if (depth > 64) fail('owned JSON depth');
      if (typeof value === 'string') {
        string(value);
        return value;
      }
      if (
        value === null ||
        typeof value === 'boolean' ||
        (typeof value === 'number' && Number.isFinite(value)) ||
        typeof value === 'bigint'
      ) {
        quota.charge(
          typeof value === 'bigint' ? value.toString().length : JSON.stringify(value).length,
        );
        return value;
      }
      if (!value || typeof value !== 'object') fail('expected owned JSON data');
      if (ancestors.has(value)) fail('cyclic owned JSON data');
      const array = Array.isArray(value),
        proto = Object.getPrototypeOf(value);
      if (array ? !Array.isArray(proto) : proto !== null && Object.getPrototypeOf(proto) !== null)
        fail('expected ordinary JSON data');
      ancestors.add(value);
      const length = array ? Object.getOwnPropertyDescriptor(value, 'length').value : null;
      if (array && length > quota.remaining) fail('byte budget');
      const keys = Reflect.ownKeys(value);
      if (array && keys.length !== length + 1) fail('expected dense JSON array');
      const count = array ? length : keys.length,
        out = array ? [] : {};
      quota.charge(2 + Math.max(0, count - 1));
      for (let i = 0; i < count; i++) {
        const key = array ? String(i) : keys[i];
        if (typeof key !== 'string') fail('expected JSON property name');
        const child = ownValue(value, key);
        if (array) out.push(visit(child, depth + 1));
        else {
          string(key);
          quota.charge(1);
          Object.defineProperty(out, key, {
            value: visit(child, depth + 1),
            enumerable: true,
            writable: true,
            configurable: true,
          });
        }
      }
      ancestors.delete(value);
      return out;
    }
    return visit(value, 0);
  }
  const capturedStudies = new WeakSet(),
    capturedManifests = new WeakSet(),
    capturedViews = new WeakSet();
  function captureIdentity(identity, study = false) {
    const required = ['publication', 'generated_at'],
      optional = study
        ? ['definition']
        : ['observation_end', 'definition_sha256', 'content_sha256'];
    if (study) required.push('observation_end', 'selection');
    const result = Object.fromEntries(required.map((key) => [key, ownValue(identity, key)]));
    for (const key of optional) {
      const value = ownValue(identity, key, false);
      if (value !== undefined) result[key] = value;
    }
    return snapshot(result, MANIFEST_MAX);
  }
  function captureStudy(study) {
    if (capturedStudies.has(study)) return study;
    const captured = freeze(captureIdentity(study, true));
    capturedStudies.add(captured);
    return captured;
  }
  function isOrdinaryStudy(study) {
    return ownValue(ownValue(study, 'selection'), 'requested_cve_ids') === null;
  }

  function fields(value, names) {
    if (
      !value ||
      typeof value !== 'object' ||
      Array.isArray(value) ||
      Object.keys(value).length !== names.length ||
      names.some((name) => !Object.hasOwn(value, name))
    )
      fail('invalid descriptor fields');
  }
  function hash(value) {
    if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('invalid fingerprint');
  }
  function limit(value, maximum) {
    if (!Number.isSafeInteger(value) || value < 1 || value > maximum) fail('byte budget');
    return value;
  }
  function decodedDescriptor(value, max) {
    fields(value, ['bytes', 'sha256']);
    limit(value.bytes, max);
    hash(value.sha256);
  }
  function key(vendor, scope, window) {
    return JSON.stringify([vendor, scope, window]);
  }
  function checkCohort(selection, options, observationEnd) {
    fields(options, ['vendor', 'scope_level', 'window', 'cve_ids']);
    const { vendor, scope_level, window, cve_ids } = options;
    if (
      (vendor !== null && !vendors.includes(vendor)) ||
      !scopes.includes(scope_level) ||
      cve_ids !== null
    )
      fail('invalid view options');
    S.bounds(D, observationEnd, window);
    fields(selection, [
      'requested_vendor',
      'effective_vendors',
      'scope_level',
      'requested_window',
      'effective_windows',
      'requested_cve_ids',
      'effective_cve_ids',
      'definition_sha256',
    ]);
    const effective = vendor === null ? vendors : [vendor],
      cves = selection.effective_cve_ids;
    if (
      selection.requested_vendor !== vendor ||
      selection.scope_level !== scope_level ||
      selection.requested_window !== window ||
      selection.requested_cve_ids !== null ||
      selection.definition_sha256 !== C.policy.definition_sha256 ||
      !eq(selection.effective_vendors, effective) ||
      !eq(
        selection.effective_windows,
        effective.map((v) => `${v}:${scope_level}:${window}`),
      ) ||
      !Array.isArray(cves) ||
      cves.some(
        (cve, index) =>
          typeof cve !== 'string' ||
          !/^CVE-\d{4}-\d{4,19}$/.test(cve) ||
          (index > 0 && cve <= cves[index - 1]),
      )
    )
      fail('view cohort differs');
  }
  function checkView(view, observationEnd, physical = new Map()) {
    fields(view, ['options', 'selection', 'decoded', 'chunks']);
    checkCohort(view.selection, view.options, observationEnd);
    decodedDescriptor(view.decoded, MAX);
    const total = view.decoded.bytes;
    if (!Array.isArray(view.chunks) || view.chunks.length !== Math.ceil(total / SLICE))
      fail('slice count differs');
    for (const [i, chunk] of view.chunks.entries()) {
      fields(chunk, ['offset', 'decoded', 'part']);
      const offset = i * SLICE,
        size = Math.min(SLICE, total - offset);
      if (chunk.offset !== offset) fail('slice offset differs');
      decodedDescriptor(chunk.decoded, size);
      if (chunk.decoded.bytes !== size) fail('slice size differs');
      window.InfrastructurePublicationV2.descriptor(chunk.part, true);
      const prior = physical.get(chunk.part.path);
      if (prior && (!eq(prior.part, chunk.part) || !eq(prior.decoded, chunk.decoded)))
        fail('conflicting slice descriptor');
      physical.set(chunk.part.path, chunk);
    }
  }
  function validateManifest(manifest, identity) {
    manifest = snapshot(manifest, MANIFEST_MAX);
    identity = captureIdentity(identity);
    fields(manifest, [
      'schema_version',
      'representation',
      'publication',
      'generated_at',
      'definition_sha256',
      'observation_end',
      'source_content_sha256',
      'views',
    ]);
    C.identity(manifest, identity);
    checkCutoff(manifest);
    if (manifest.publication !== null) {
      fields(manifest.publication, ['id', 'advisory_schema_version']);
      if (
        typeof manifest.publication.id !== 'string' ||
        !/^[0-9a-f]{32}$/.test(manifest.publication.id) ||
        manifest.publication.advisory_schema_version !== 2
      )
        fail('invalid publication');
    }
    if (
      manifest.schema_version !== 1 ||
      manifest.representation !== 'analysis-selected-delivery' ||
      manifest.definition_sha256 !== C.policy.definition_sha256 ||
      (Object.hasOwn(identity, 'observation_end') &&
        identity.observation_end !== manifest.observation_end) ||
      (Object.hasOwn(identity, 'definition_sha256') &&
        identity.definition_sha256 !== manifest.definition_sha256) ||
      (Object.hasOwn(identity, 'content_sha256') &&
        identity.content_sha256 !== manifest.source_content_sha256)
    )
      fail('manifest identity or cutoff differs');
    hash(manifest.source_content_sha256);
    if (!Array.isArray(manifest.views) || manifest.views.length < 1 || manifest.views.length > 32)
      fail('invalid manifest view count');
    const seen = new Set(),
      physical = new Map();
    for (const view of manifest.views) {
      checkView(view, manifest.observation_end, physical);
      const option = view.options,
        k = key(option.vendor, option.scope_level, option.window);
      if (seen.has(k)) fail('duplicate view options');
      seen.add(k);
    }
    freeze(manifest);
    capturedManifests.add(manifest);
    for (const view of manifest.views) capturedViews.add(view);
    return manifest;
  }
  function matchView(manifest, study) {
    study = captureStudy(study);
    if (!capturedManifests.has(manifest)) manifest = validateManifest(manifest, study);
    const selection = study.selection;
    if (selection.requested_cve_ids !== null) return null;
    const id = key(selection.requested_vendor, selection.scope_level, selection.requested_window),
      view = manifest.views.find(({ options: o }) => key(o.vendor, o.scope_level, o.window) === id);
    if (view) {
      C.identity(manifest, study);
      if (manifest.observation_end !== study.observation_end || !eq(view.selection, selection))
        fail('accepted cohort or cutoff differs');
    }
    return view ?? null;
  }

  // DecompressionStream accepts concatenated members in some runtimes. Walk
  // the deflate block boundaries without expanding bytes so even an appended
  // empty member, or an empty first member, cannot satisfy the wire contract.
  const codeOrder = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
  const FAST_BITS = 9;
  function huffman(lengths, charge = () => {}) {
    const width = Math.max(...lengths),
      fastWidth = Math.min(width, FAST_BITS),
      size = 1 << fastWidth;
    // Canonical tables use one entry per symbol plus a small fast prefix.
    // Bound both table creation and symbol indexing against compressed input.
    charge(2 * size + 4 * lengths.length + 8 * width);
    const counts = new Uint16Array(width + 1),
      first = new Uint16Array(width + 1),
      offset = new Uint16Array(width + 1);
    for (const n of lengths) if (n) counts[n]++;
    for (let n = 1; n <= width; n++) {
      first[n] = (first[n - 1] + counts[n - 1]) * 2;
      offset[n] = offset[n - 1] + counts[n - 1];
    }
    const next = first.slice(),
      write = offset.slice(),
      symbols = new Uint16Array(lengths.length),
      fast = new Uint16Array(size);
    for (const [symbol, n] of lengths.entries()) {
      if (!n) continue;
      let code = next[n]++;
      if (code >= 1 << n) fail('invalid gzip Huffman code');
      symbols[write[n]++] = symbol;
      if (n > fastWidth) continue;
      let reversed = 0;
      for (let j = 0; j < n; j++, code >>>= 1) reversed = (reversed << 1) | (code & 1);
      for (let i = reversed; i < size; i += 1 << n) fast[i] = (symbol << 4) | n;
    }
    return { width, counts, first, offset, symbols, fast };
  }
  const fixed = [
    huffman(Array.from({ length: 288 }, (_, i) => (i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8))),
    huffman(Array(32).fill(5)),
  ];
  const matchLengths = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
  ];
  async function singleMember(wire, expected, run) {
    const header = [31, 139, 8, 0, 0, 0, 0, 0, 0, 255],
      end = (wire.length - 8) * 8;
    if (wire.length < 20 || header.some((v, i) => wire[i] !== v)) fail('invalid gzip header');
    const interval = 131072,
      allowance = 64 * wire.length + 32768;
    let position = 80,
      produced = 0,
      work = 0,
      checkpoint = interval;
    function charge(n) {
      work += n;
      if (work > allowance) fail('gzip preflight work budget');
    }
    async function pause() {
      await run(new Promise((resolve) => setTimeout(resolve, 0)));
      checkpoint = work + interval;
    }
    function peek() {
      const i = position >>> 3;
      return (wire[i] | (wire[i + 1] << 8) | (wire[i + 2] << 16)) >>> (position & 7);
    }
    function bits(n) {
      const value = peek() & ((1 << n) - 1);
      position += n;
      if (position > end) fail('truncated gzip member');
      return value;
    }
    function symbol(table) {
      charge(1);
      let bits = peek(),
        entry = table.fast[bits & (table.fast.length - 1)];
      if (!entry && table.width > FAST_BITS) {
        charge(table.width);
        let code = 0;
        for (let n = 1; n <= table.width; n++, bits >>>= 1) {
          code = (code << 1) | (bits & 1);
          if (n > FAST_BITS) {
            const index = code - table.first[n];
            if (index >= 0 && index < table.counts[n]) {
              entry = (table.symbols[table.offset[n] + index] << 4) | n;
              break;
            }
          }
        }
      }
      const n = entry & 15;
      position += n;
      if (!n || position > end) fail('invalid gzip Huffman symbol');
      return entry >>> 4;
    }
    function dynamic() {
      const literals = bits(5) + 257,
        distances = bits(5) + 1,
        count = bits(4) + 4,
        codeLengths = Array(19).fill(0);
      for (let i = 0; i < count; i++) codeLengths[codeOrder[i]] = bits(3);
      const table = huffman(codeLengths, charge),
        lengths = [];
      while (lengths.length < literals + distances) {
        const code = symbol(table);
        if (code < 16) lengths.push(code);
        else {
          const previous = lengths.at(-1);
          if (code === 16 && previous === undefined) fail('invalid gzip code repeat');
          const repeats = code === 16 ? bits(2) + 3 : code === 17 ? bits(3) + 3 : bits(7) + 11;
          for (let j = 0; j < repeats; j++) lengths.push(code === 16 ? previous : 0);
        }
      }
      if (lengths.length !== literals + distances || !lengths[256]) fail('invalid gzip codes');
      return [
        huffman(lengths.slice(0, literals), charge),
        huffman(lengths.slice(literals), charge),
      ];
    }
    let final;
    do {
      if (work >= checkpoint) await pause();
      charge(8);
      final = bits(1);
      const type = bits(2);
      if (type === 0) {
        position = (position + 7) & ~7;
        const length = bits(16);
        if (bits(16) !== (length ^ 65535)) fail('invalid gzip stored block');
        position += length * 8;
        produced += length;
        if (produced > expected) fail('decoded gzip byte budget');
        if (position > end) fail('truncated gzip stored block');
        continue;
      }
      if (type === 3) fail('invalid gzip block type');
      const [literal, distance] = type === 1 ? fixed : dynamic();
      for (;;) {
        if (work >= checkpoint) await pause();
        const code = symbol(literal);
        if (code < 256) {
          if (++produced > expected) fail('decoded gzip byte budget');
          continue;
        }
        if (code === 256) break;
        if (code > 285) fail('invalid gzip match length');
        const i = code - 257;
        produced += matchLengths[i] + (i >= 8 && i !== 28 ? bits((i - 4) >>> 2) : 0);
        if (produced > expected) fail('decoded gzip byte budget');
        const d = symbol(distance);
        if (d > 29) fail('invalid gzip distance');
        if (d >= 4) bits((d >>> 1) - 1);
      }
    } while (!final);
    if (((position + 7) & ~7) !== end) fail('trailing gzip member or bytes');
    if (produced !== expected) fail('decoded gzip length differs');
  }

  function supported() {
    return (
      typeof DecompressionStream === 'function' &&
      typeof Response === 'function' &&
      typeof crypto === 'object' &&
      !!crypto.subtle
    );
  }
  async function digest(raw) {
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)), (byte) =>
      byte.toString(16).padStart(2, '0'),
    ).join('');
  }
  const typedArray = Object.getPrototypeOf(Uint8Array.prototype),
    typedGetter = (key) => Object.getOwnPropertyDescriptor(typedArray, key).get,
    typedName = typedGetter(Symbol.toStringTag),
    typedLength = typedGetter('byteLength'),
    typedOffset = typedGetter('byteOffset'),
    typedBuffer = typedGetter('buffer');
  function ownWire(value, length) {
    if (
      !ArrayBuffer.isView(value) ||
      typedName.call(value) !== 'Uint8Array' ||
      typedLength.call(value) !== length
    )
      fail('wire byte size differs');
    // Use typed array intrinsics so user getters, iterators and a later
    // mutation of borrowed storage cannot change the authenticated gzip.
    const wire = new Uint8Array(length);
    wire.set(new Uint8Array(typedBuffer.call(value), typedOffset.call(value), length));
    return wire;
  }
  async function verify(raw, descriptor, run) {
    if (
      !ArrayBuffer.isView(raw) ||
      raw.BYTES_PER_ELEMENT !== 1 ||
      raw.byteLength !== descriptor.bytes ||
      (await run(digest(raw))) !== descriptor.sha256
    )
      fail('bytes or fingerprint differ');
  }
  async function inflate(wire, destination, chunk, run) {
    await singleMember(wire, destination.length, run);
    const reader = new Response(wire).body.pipeThrough(new DecompressionStream('gzip')).getReader();
    let used = 0;
    try {
      for (;;) {
        const { value, done } = await run(
          reader.read().catch((error) => {
            throw Error('Selected analysis: invalid gzip output', { cause: error });
          }),
        );
        if (done) break;
        if (value.length > destination.length - used) fail('decoded gzip byte budget');
        destination.set(value, used);
        used += value.length;
      }
    } finally {
      try {
        Promise.resolve(reader.cancel()).catch(() => {});
      } catch {}
      try {
        reader.releaseLock();
      } catch {}
    }
    if (used !== destination.length) fail('decoded slice length differs');
    await verify(destination, chunk.decoded, run);
  }

  function checkCutoff(identity) {
    if (
      typeof identity.generated_at !== 'string' ||
      typeof identity.observation_end !== 'string' ||
      S.day(identity.generated_at) !== identity.observation_end ||
      identity.observation_end < D.start_date
    )
      fail('observation cutoff differs');
  }
  function checkStudy(study) {
    checkCutoff(study);
    const s = study.selection;
    if (!s || typeof s !== 'object') fail('invalid study cohort');
    if (
      Object.hasOwn(study, 'definition') &&
      C.fingerprint(study.definition) !== C.policy.definition_sha256
    )
      fail('study definition differs');
    checkCohort(
      s,
      {
        vendor: s.requested_vendor,
        scope_level: s.scope_level,
        window: s.requested_window,
        cve_ids: s.requested_cve_ids,
      },
      study.observation_end,
    );
  }
  function disclosurePeriod(day) {
    return day === null ? 'unknown' : day < '2026-07-01' ? 'pre_july' : 'from_july';
  }
  function checkDisclosure(report, domain, effective, dateOK) {
    const A = window.InfrastructureSwitchingAnalysis,
      facts = new Map(report.advisory_facts.map((f) => [f.id, f])),
      used = new Set(),
      pairs = new Set(),
      claimIds = new Set(),
      affected = new Map();
    for (const p of report.pairs) {
      const f = facts.get(p.fact_id),
        date = S.day(p.initial_published_at),
        key = JSON.stringify([
          p.vendor,
          p.family,
          p.advisory_id,
          p.cve_id,
          p.source.source_url,
          p.source.source_sha256,
        ]),
        umbrella = f?.metadata.umbrella_cves.find((u) => u.cve_id === p.cve_id) ?? null;
      if (
        !domain(p) ||
        !effective.has(p.cve_id) ||
        !dateOK(date) ||
        p.date_period !== disclosurePeriod(date) ||
        pairs.has(key) ||
        !p.claim_ids.length ||
        p.claim_ids.some((id) => claimIds.has(id)) ||
        !eq(p.umbrella, umbrella) ||
        (p.fact_id !== null &&
          (!f ||
            f.vendor !== p.vendor ||
            f.advisory_id !== p.advisory_id ||
            f.source.source_url !== p.source.source_url ||
            f.source.source_sha256 !== p.source.source_sha256 ||
            f.metadata.initial_published_at !== p.initial_published_at ||
            !eq(f.metadata.method, p.method)))
      )
        fail('disclosure ownership differs');
      pairs.add(key);
      for (const id of p.claim_ids) claimIds.add(id);
      if (!affected.has(p.vendor)) affected.set(p.vendor, new Set());
      affected.get(p.vendor).add(p.cve_id);
      if (p.fact_id !== null) used.add(p.fact_id);
    }
    if (used.size !== facts.size || facts.size !== report.advisory_facts.length)
      fail('disclosure reference closure differs');
    for (const bundle of report.bundles) {
      const memberIds = new Set(bundle.member_advisory_ids),
        members = report.pairs.filter(
          (p) =>
            p.vendor === bundle.vendor &&
            p.family === bundle.family &&
            memberIds.has(p.advisory_id),
        );
      if (
        !domain(bundle) ||
        !members.length ||
        bundle.date_period !== disclosurePeriod(S.day(bundle.initial_published_at)) ||
        !eq(bundle.selected_advisory_ids, sorted(members.map((p) => p.advisory_id))) ||
        !eq(bundle.selected_cve_ids, sorted(members.map((p) => p.cve_id)))
      )
        fail('disclosure bundle ownership differs');
      if (bundle.kind === 'security_hardening') {
        const owners = report.advisory_facts.filter(
            (f) =>
              f.vendor === bundle.vendor &&
              f.advisory_id === bundle.publisher_id &&
              eq(f.source, bundle.source),
          ),
          metadata = owners[0]?.metadata.bundle;
        if (
          owners.length !== 1 ||
          !metadata ||
          bundle.initial_published_at !== metadata.initial_published_at ||
          !eq(bundle.member_advisory_ids, metadata.advisory_ids) ||
          !eq(bundle.member_cve_ids, metadata.cve_ids)
        )
          fail('disclosure hardening bundle ownership differs');
      }
    }
    for (const [name, expected] of Object.entries(
      A.disclosureAggregates(report.pairs, report.advisory_facts),
    ))
      if (!eq(report[name], expected)) fail('disclosure ' + name + ' differs');
    return affected;
  }
  function checkModels(report, vendorOK, effective) {
    const expectedModels = D.targets
      .filter((t) => vendorOK(t.vendor))
      .flatMap((t) => t.models.map((model) => [t.vendor, t.family, model]));
    if (
      !eq(
        report.models.map((m) => [m.vendor, m.family, m.model]),
        expectedModels,
      )
    )
      fail('model coverage target ownership differs');

    function claimsIn(row) {
      const ids = new Set(row.claim_ids),
        n = ids.size,
        count = row.counts;
      if (
        n !== row.claim_ids.length ||
        n !== count.claims ||
        count.advisories > n ||
        count.cves > n
      )
        fail('model coverage claim counts differ');
      if (row.by_status) {
        const statuses = Object.values(row.by_status);
        if (
          statuses.reduce((total, v) => total + v.claims, 0) !== n ||
          statuses.some(
            (v) =>
              v.advisories > Math.min(v.claims, count.advisories) ||
              v.cves > Math.min(v.claims, count.cves),
          )
        )
          fail('model coverage status counts differ');
      }
      return ids;
    }

    const bound = new Set(),
      unresolved = new Set(),
      advisories = new Set();
    for (const row of report.models) {
      const ids = claimsIn(row);
      if (
        row.counts.advisories !== row.advisory_ids.length ||
        row.counts.cves !== row.cve_ids.length ||
        new Set(row.advisory_ids).size !== row.advisory_ids.length ||
        new Set(row.cve_ids).size !== row.cve_ids.length ||
        row.cve_ids.some((id) => !effective.has(id))
      )
        fail('model coverage row ownership differs');
      for (const source of row.by_source) {
        if (
          [...claimsIn(source)].some((id) => !ids.has(id)) ||
          source.counts.advisories > row.counts.advisories ||
          source.counts.cves > row.counts.cves
        )
          fail('model coverage source ownership differs');
      }
      for (const id of ids) bound.add(id);
      for (const id of row.advisory_ids) advisories.add(JSON.stringify([row.vendor, id]));
    }
    for (const row of report.unresolved) for (const id of claimsIn(row)) unresolved.add(id);
    const total = report.totals;
    if (
      [...unresolved].some((id) => bound.has(id)) ||
      total.bound_claims !== bound.size ||
      total.unresolved_claims !== unresolved.size ||
      total.claims !== bound.size + unresolved.size ||
      total.cves !== effective.size ||
      total.advisories < advisories.size ||
      total.advisories > advisories.size + unresolved.size
    )
      fail('model coverage union counts differ');
  }

  // Exact public CISA pair labels from switching_kev_reconciliation.RULES.
  const ciscoKevLabels = [
    'Cisco IOS XE Web UI',
    'IOS Software and Cisco IOS XE Software',
    'IOS XE Software',
    'IOS XE Web UI',
    'IOS and IOS XE',
    'IOS and IOS XE Software',
    'IOS, IOS XR, and IOS XE',
    'IOS, XR, and XE Software',
  ];
  function mapping({ vendorProject, product }) {
    const rank = vendorProject === 'Cisco' ? ciscoKevLabels.indexOf(product) + 1 : 0;
    if (rank)
      return {
        status: 'mapped',
        rule_id: 'cisco-iosxe-' + rank,
        vendor: 'cisco',
        family: 'cisco-iosxe',
      };
    if (vendorProject === 'Arista' && product === 'Extensible Operating System')
      return { status: 'mapped', rule_id: 'arista-eos-1', vendor: 'arista', family: 'arista-eos' };
    return { status: 'unmapped', rule_id: null, vendor: null, family: null };
  }
  function checkKev(kev, study, domain, effective) {
    const A = window.InfrastructureSwitchingAnalysis,
      status = window.InfrastructureKev.reportAvailability(kev);
    if (
      kev.evaluated_at !== study.generated_at ||
      kev.mapping_version !== 'switching-kev-exact-pairs-v1' ||
      kev.availability !== status ||
      kev.source.availability !== status
    )
      fail('KEV availability or mapping policy differs');
    if (!eq(kev.summary, A.kevSummary(kev.entries))) fail('KEV summary differs');
    if (
      kev.entries.some(
        (entry, i) =>
          (i > 0 && kev.entries[i - 1].cve_id >= entry.cve_id) ||
          !eq(entry.mapping, mapping(entry)) ||
          (entry.mapping.status === 'mapped' && !domain(entry.mapping)) ||
          !entry.in_requested_cve_filter ||
          entry.in_effective_study_cohort !== effective.has(entry.cve_id) ||
          entry.membership !== (status === 'available' ? 'listed' : 'unknown'),
      )
    )
      fail('KEV mapping or membership differs');
  }

  function checkChildren(report, study) {
    const A = window.InfrastructureSwitchingAnalysis,
      selection = study.selection,
      end = study.observation_end,
      [start, stop] = S.bounds(D, end, selection.requested_window),
      vendorOK = (v) => selection.effective_vendors.includes(v),
      domain = (v) => vendorOK(v.vendor) && families[v.vendor] === v.family,
      effective = new Set(selection.effective_cve_ids),
      dateOK = (date) => S.inWindow(date, start, stop, selection.requested_window),
      children = [
        'upgrades',
        'disclosure',
        'model_coverage',
        'kev_reconciliation',
        'release_history',
      ];
    C.identity(report, study);
    if (report.availability !== 'available' || !eq(report.selection, selection))
      fail('report cohort differs');
    for (const name of children) {
      const child = report[name];
      if (!child) fail('missing ' + name);
      C.identity(child, study);
      if (
        child.observation_end !== end ||
        child.definition_sha256 !== C.policy.definition_sha256 ||
        !eq(child.selection, selection)
      )
        fail(name + ' cohort or cutoff differs');
    }
    const upgrades = report.upgrades,
      compact = upgrades.requirements;
    if (upgrades.availability !== 'available' || !compact) fail('missing selected requirements');
    C.identity(compact, study);
    if (
      compact.selection !== null ||
      compact.observation_end !== end ||
      compact.definition_sha256 !== C.policy.definition_sha256 ||
      compact.kev_context.evaluated_at !== study.generated_at
    )
      fail('requirements bounds differ');
    const fromYear = Number((start ?? D.start_date).slice(0, 4)),
      throughYear = Number((stop ?? end).slice(0, 4));
    for (const m of Object.values(compact.members))
      if (
        !domain(m) ||
        (selection.scope_level === 'model_qualified' && m.scope_level !== 'model_qualified') ||
        (m.date !== null && !(D.start_date <= m.date && m.date <= end))
      )
        fail('selected member outside study');
    for (const row of upgrades.rows)
      if (
        !domain(row) ||
        row.year < fromYear ||
        row.year > throughYear ||
        row.events.some(
          (event) => !dateOK(event.date) || Number(event.date.slice(0, 4)) !== row.year,
        )
      )
        fail('selected row outside study');
    A.checkSelectedUpgrades(upgrades, { shapeChecked: true, checkConstraintsToo: true });

    const affected = checkDisclosure(report.disclosure, domain, effective, dateOK);
    checkModels(report.model_coverage, vendorOK, effective);
    checkKev(report.kev_reconciliation, study, domain, effective);

    const history = report.release_history;
    window.InfrastructureCustomerComparison.checkHistory(history, study);
    if (
      [...history.releases, ...history.bundles, ...history.platform_support].some(
        (node) => !domain(node),
      ) ||
      history.releases.some(
        (node) =>
          (!node.history.length && !node.references.length) ||
          node.references.some(
            (ref) =>
              !(ref.kind === 'vendor_fixed' ? effective : affected.get(node.vendor))?.has(
                ref.cve_id,
              ) ||
              !dateOK(S.day(ref.initial_published_at)) ||
              (selection.scope_level === 'model_qualified' &&
                ref.scope_level !== 'model_qualified'),
          ),
      )
    )
      fail('release history outside study');
    return compact;
  }

  function freeze(value) {
    if (value && typeof value === 'object') {
      for (const child of Object.values(value)) freeze(child);
      Object.freeze(value);
    }
    return value;
  }
  const verified = new WeakSet();
  const copy = (value) =>
    typeof structuredClone === 'function' ? structuredClone(value) : J.clone(value);
  function prepareOwned(report, study, max_bytes) {
    const max = limit(max_bytes, MAX),
      bytes = J.measure(report, null, '', max);
    C.validate('switching-analysis-v1.json', report, '/$defs/selected');
    const compact = checkChildren(report, study),
      facts = {};
    // Match the compiled browser selector's insertion order for JSON downloads;
    // retain native ordering inside every fact and in the wire document.
    for (const m of Object.values(compact.members))
      for (const k of ['source_ref', 'severity_facets_ref']) facts[m[k]] = compact.facts[m[k]];
    for (const r of compact.requirements)
      for (const k of ['proof_ref', 'train_binding_ref']) facts[r[k]] = compact.facts[r[k]];
    compact.facts = facts;
    const prepared = Object.freeze({ value: freeze(report), bytes });
    verified.add(prepared);
    return prepared;
  }
  function prepareSelected(report, study, max_bytes = MAX) {
    const accepted = captureStudy(study);
    checkStudy(accepted);
    return prepareOwned(snapshot(report, limit(max_bytes, MAX)), accepted, max_bytes);
  }
  function copySelected(prepared, max_bytes = MAX) {
    if (!verified.has(prepared)) fail('expected prepared report');
    limit(prepared.bytes, limit(max_bytes, MAX));
    return copy(prepared.value);
  }
  async function decodeSelected(
    view,
    study,
    load,
    { max_bytes = MAX, run = (promise) => promise } = {},
  ) {
    // Snapshot borrowed metadata before invoking a fetch or yielding.
    if (!capturedViews.has(view)) view = freeze(snapshot(view, MANIFEST_MAX));
    study = captureStudy(study);
    checkStudy(study);
    checkView(view, study.observation_end);
    if (!eq(view.selection, study.selection)) fail('accepted cohort differs');
    limit(view.decoded.bytes, limit(max_bytes, MAX));
    const output = new Uint8Array(view.decoded.bytes);
    for (const chunk of view.chunks) {
      const wire = ownWire(await run(load(chunk.part)), chunk.part.bytes);
      await verify(wire, chunk.part, run);
      await inflate(
        wire,
        output.subarray(chunk.offset, chunk.offset + chunk.decoded.bytes),
        chunk,
        run,
      );
    }
    await verify(output, view.decoded, run);
    const selected = J.parseStrict(
      new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(output),
    );
    return run(Promise.resolve(prepareOwned(selected, study, max_bytes)));
  }

  window.InfrastructureAnalysisPrecomputed = {
    ROOT,
    MANIFEST_MAX,
    supported,
    isOrdinaryStudy,
    captureStudy,
    validateManifest,
    matchView,
    prepareSelected,
    decodeSelected,
    copySelected,
  };
})();
