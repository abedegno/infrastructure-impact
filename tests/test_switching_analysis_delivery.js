// Actual Python publications and lazy optional transports, with no private DB/config.
const fs = require('fs'),
  vm = require('vm'),
  assert = require('assert'),
  path = require('path'),
  os = require('os'),
  child = require('child_process');
(async () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'analysis-browser-'));
  try {
    for (const format of ['v1', 'v2']) {
      const dir = child
        .execFileSync(
          '.venv/bin/python',
          [
            '-c',
            `import json,sys
sys.path.insert(0,'tests')
from test_static_delivery import dataset
from infrastructure_impact.application.publication import publish
data=dataset()
data['research']['switching_input']=json.load(open('tests/fixtures/switching-cases.json'))['evidence']
print(publish(data,sys.argv[1],publication_format=sys.argv[2],include_switching_analysis=True))`,
            path.join(temporary, format),
            format,
          ],
          {
            env: {
              ...process.env,
              IMPACT_HOME: path.join(temporary, 'home'),
              IMPACT_SOURCES: path.resolve('infrastructure_impact/resources/sources.json'),
              PYTHONPATH: process.cwd(),
            },
            encoding: 'utf8',
          },
        )
        .trim();
      const context = {
        window: {},
        TextEncoder,
        TextDecoder,
        crypto: require('crypto').webcrypto,
        AbortController,
        console,
        setTimeout,
        clearTimeout,
        URL,
      };
      vm.createContext(context);
      for (const name of [
        'lossless-json',
        'kev',
        'switching-contracts',
        'switching',
        'customer-comparison',
        'switching-analysis',
        'publication-v2',
        'delivery',
      ])
        vm.runInContext(fs.readFileSync(`infrastructure_impact/web/${name}.js`, 'utf8'), context);
      const reads = [],
        fetch = async (name) => {
          reads.push(name);
          const p = path.join(dir, name.replace(/^\//, ''));
          if (!fs.existsSync(p)) return { ok: false, status: 404 };
          const raw = fs.readFileSync(p);
          return {
            ok: true,
            status: 200,
            arrayBuffer: async () => raw,
            text: async () => raw.toString(),
          };
        };
      const loader = await context.createStaticDelivery(fetch, ''),
        index = JSON.parse(fs.readFileSync(path.join(dir, 'data/index.json')));
      const v2Catalog =
        format === 'v2' ? JSON.parse(fs.readFileSync(path.join(dir, 'publication-v2.json'))) : null;
      const analysisPaths = [
        v2Catalog
          ? v2Catalog.roots['switching-analysis.json'].path
          : index.switching_analysis.summary.path,
      ];
      assert(
        analysisPaths.every((p) => !reads.includes(p)),
        'bootstrap must not load analysis',
      );
      const study =
        format === 'v2' ? await loader.switchingOverview() : await loader.switchingSummary();
      assert(
        analysisPaths.every((p) => !reads.includes(p)),
        'default study must not load analysis',
      );
      loader.switchingClaims = () => {
        throw Error('forbidden full claim load');
      };
      loader.switchingReport = () => {
        throw Error('forbidden full report load');
      };
      const contracts = context.window.InfrastructureSwitchingContracts,
        validate = contracts.validate;
      let compiledValidations = 0;
      contracts.validate = (name, value, fragment) => {
        if (name === 'switching-analysis-v1.json' && fragment === '/$defs/compiled')
          compiledValidations++;
        return validate(name, value, fragment);
      };
      const selected = await loader.switchingAnalysis(study);
      assert.strictEqual(selected.availability, 'available');
      assert(
        analysisPaths.some((p) => reads.includes(p)),
        'explicit load reads analysis',
      );
      await assert.rejects(
        () => loader.switchingAnalysis({ ...study, generated_at: '2000-01-01T00:00:00Z' }),
        /generation|identity|publication/i,
      );
      if (format === 'v2') {
        const coldReads = reads.length;
        const expected = JSON.stringify(selected);
        selected.upgrades.requirements.kev_context.evaluated_at = 'changed-output-only';
        const repeated = await loader.switchingAnalysis(study);
        assert.strictEqual(JSON.stringify(repeated), expected);
        await assert.rejects(
          () =>
            loader.switchingAnalysis({
              ...study,
              selection: { ...study.selection, effective_cve_ids: [] },
            }),
          /accepted cohort differs/,
        );
        assert.strictEqual(reads.length, coldReads, 'repeat selections make no transport reads');
        assert.strictEqual(compiledValidations, 1, 'v2 validates a compiled root once');
        delete v2Catalog.roots['switching-analysis.json'];
        const absent = await context.window.InfrastructurePublicationV2.open(
          fetch,
          v2Catalog,
          index,
        );
        assert.strictEqual((await absent.switchingAnalysis(study)).availability, 'unavailable');
      }
      // A missing optional descriptor/root remains unavailable; a present invalid one fails.
      if (format === 'v1') {
        const rawIndex = fs.readFileSync(path.join(dir, 'data/index.json'));
        delete index.switching_analysis;
        fs.writeFileSync(path.join(dir, 'data/index.json'), JSON.stringify(index));
        const absent = await context.createStaticDelivery(fetch, '');
        assert.strictEqual((await absent.switchingAnalysis(study)).availability, 'unavailable');
        fs.writeFileSync(path.join(dir, 'data/index.json'), rawIndex);
        const original = JSON.parse(rawIndex).switching_analysis.summary,
          part = path.join(dir, original.path);
        fs.appendFileSync(part, ' ');
        const tampered = await context.createStaticDelivery(fetch, '');
        await assert.rejects(() => tampered.switchingAnalysis(study), /size|fingerprint/);
      }
    }
    console.log(
      'Actual v1/v2 lazy analysis, no full claim load, missing/tampered/mixed generation passed',
    );
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
