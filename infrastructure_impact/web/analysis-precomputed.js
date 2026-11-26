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
      typeof manifest.observation_end !== 'string' ||
      S.day(manifest.generated_at) !== manifest.observation_end ||
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
    J.measure(manifest, null, '', MANIFEST_MAX);
    return manifest;
  }
  function matchView(manifest, study) {
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
  function huffman(lengths) {
    const width = Math.max(...lengths),
      counts = new Uint16Array(width + 1);
    for (const n of lengths) if (n) counts[n]++;
    const next = new Uint16Array(width + 1);
    for (let n = 1; n <= width; n++) next[n] = (next[n - 1] + counts[n - 1]) * 2;
    const entries = new Uint16Array(1 << width);
    for (const [symbol, n] of lengths.entries()) {
      if (!n) continue;
      let code = next[n]++,
        reversed = 0;
      if (code >= 1 << n) fail('invalid gzip Huffman code');
      for (let j = 0; j < n; j++, code >>>= 1) reversed = (reversed << 1) | (code & 1);
      for (let i = reversed; i < entries.length; i += 1 << n) entries[i] = (symbol << 4) | n;
    }
    return entries;
  }
  const fixed = [
    huffman(Array.from({ length: 288 }, (_, i) => (i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8))),
    huffman(Array(32).fill(5)),
  ];
  const matchLengths = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
  ];
  function singleMember(wire, expected) {
    const header = [31, 139, 8, 0, 0, 0, 0, 0, 0, 255],
      end = (wire.length - 8) * 8;
    if (wire.length < 20 || header.some((v, i) => wire[i] !== v)) fail('invalid gzip header');
    let position = 80,
      produced = 0;
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
      const value = table[peek() & (table.length - 1)],
        n = value & 15;
      position += n;
      if (!n || position > end) fail('invalid gzip Huffman symbol');
      return value >>> 4;
    }
    function dynamic() {
      const literals = bits(5) + 257,
        distances = bits(5) + 1,
        count = bits(4) + 4,
        codeLengths = Array(19).fill(0);
      for (let i = 0; i < count; i++) codeLengths[codeOrder[i]] = bits(3);
      const table = huffman(codeLengths),
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
      return [huffman(lengths.slice(0, literals)), huffman(lengths.slice(literals))];
    }
    let final;
    do {
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
    singleMember(wire, destination.length);
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

    const disclosure = report.disclosure,
      facts = new Map(disclosure.advisory_facts.map((f) => [f.id, f])),
      used = new Set();
    for (const p of disclosure.pairs) {
      const f = facts.get(p.fact_id);
      if (
        !domain(p) ||
        !effective.has(p.cve_id) ||
        !dateOK(S.day(p.initial_published_at)) ||
        !p.claim_ids.length ||
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
      if (p.fact_id !== null) used.add(p.fact_id);
    }
    if (
      used.size !== facts.size ||
      facts.size !== disclosure.advisory_facts.length ||
      disclosure.bundles.some(
        (b) => !domain(b) || b.selected_cve_ids.some((id) => !effective.has(id)),
      )
    )
      fail('disclosure reference closure differs');
    if (
      disclosure.coverage.owned_source_pairs !== disclosure.pairs.length ||
      disclosure.coverage.metadata_advisories !== facts.size
    )
      fail('disclosure totals differ');

    const coverage = report.model_coverage,
      expectedModels = D.targets
        .filter((t) => vendorOK(t.vendor))
        .flatMap((t) => t.models.map((model) => [t.vendor, t.family, model]));
    if (
      !eq(
        coverage.models.map((m) => [m.vendor, m.family, m.model]),
        expectedModels,
      ) ||
      coverage.totals.cves !== effective.size ||
      coverage.models.some(
        (m) =>
          m.cve_ids.some((cve) => !effective.has(cve)) ||
          m.by_source.some((s) => s.claim_ids.some((id) => !m.claim_ids.includes(id))),
      )
    )
      fail('model coverage ownership differs');

    const kev = report.kev_reconciliation,
      mapped = kev.entries.filter((entry) => entry.mapping.status === 'mapped');
    if (
      kev.evaluated_at !== study.generated_at ||
      mapped.some((entry) => !domain(entry.mapping)) ||
      kev.entries.some(
        (entry) =>
          !entry.in_requested_cve_filter ||
          entry.in_effective_study_cohort !== effective.has(entry.cve_id),
      ) ||
      kev.summary.entry_count !== kev.entries.length ||
      kev.summary.candidate_cves !== new Set(mapped.map((entry) => entry.cve_id)).size ||
      kev.summary.unmapped_entries !== kev.entries.length - mapped.length ||
      kev.summary.unknown_membership_entries !==
        kev.entries.filter((entry) => entry.membership === 'unknown').length
    )
      fail('KEV ownership or totals differ');

    const history = report.release_history;
    window.InfrastructureCustomerComparison.checkHistory(history, study);
    if (
      [...history.releases, ...history.bundles, ...history.platform_support].some(
        (node) => !domain(node),
      ) ||
      history.releases.some((node) =>
        node.references.some(
          (ref) =>
            !effective.has(ref.cve_id) ||
            !dateOK(S.day(ref.initial_published_at)) ||
            (selection.scope_level === 'model_qualified' && ref.scope_level !== 'model_qualified'),
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
    J.measure(report, null, '', limit(max_bytes, MAX));
    return prepareOwned(copy(report), study, max_bytes);
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
    // Snapshot metadata before invoking a fetch or yielding to another caller.
    view = freeze(J.clone(view));
    study = J.clone({
      publication: study.publication,
      generated_at: study.generated_at,
      observation_end: study.observation_end,
      selection: study.selection,
    });
    checkView(view, study.observation_end);
    if (!eq(view.selection, study.selection)) fail('accepted cohort differs');
    limit(view.decoded.bytes, limit(max_bytes, MAX));
    const output = new Uint8Array(view.decoded.bytes);
    for (const chunk of view.chunks) {
      const wire = await run(load(chunk.part));
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
    validateManifest,
    matchView,
    prepareSelected,
    decodeSelected,
    copySelected,
  };
})();
