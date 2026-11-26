/* Dedicated classic worker. The publication writer includes its exact reader modules. */
(() => {
  const P = window.InfrastructureAnalysisPrecomputed;
  let prepared, selectedKey, generation, chunkReply;
  self.onmessage = async ({ data }) => {
    const { id, key, type } = data;
    const reply = (type, fields, transfer) =>
      self.postMessage({ id, generation, key, type, ...fields }, transfer);
    try {
      generation ??= data.generation;
      if (generation !== data.generation) throw Error('Analysis worker generation differs');
      if (type === 'chunk') {
        if (
          !chunkReply ||
          chunkReply.id !== id ||
          chunkReply.key !== key ||
          chunkReply.index !== data.index
        )
          throw Error('Unexpected analysis worker chunk');
        const { resolve } = chunkReply;
        chunkReply = null;
        resolve(data.bytes);
        return;
      }
      if (generation !== JSON.stringify([data.study.publication?.id, data.study.generated_at]))
        throw Error('Analysis worker study generation differs');
      if (type === 'prepare') {
        if (key !== data.view.decoded.sha256)
          throw Error('Analysis worker view fingerprint differs');
        prepared = null;
        selectedKey = null;
        let index = 0;
        const load = () =>
          new Promise((resolve) => {
            chunkReply = { id, key, resolve, index };
            reply('load', { index: index++ });
          });
        prepared = await P.decodeSelected(data.view, data.study, load, { max_bytes: data.max });
        selectedKey = key;
        reply('ready', {});
        return;
      }
      if (type !== 'deliver' || !prepared || selectedKey !== key)
        throw Error('Analysis worker selected view differs');
      const value = P.selectedValue(prepared, data.study, data.max);
      if (data.format === 'report') {
        reply('result', { value });
        return;
      }
      let text;
      if (data.format === 'json')
        text = window.InfrastructureJSON.stringifyBounded(value, null, '', data.max);
      else if (data.format === 'csv' || data.format === 'upgrades-csv')
        text = window.InfrastructureSwitchingAnalysis.csv(value, {
          upgradesOnly: data.format === 'upgrades-csv',
          max_bytes: data.max,
        });
      else throw Error('Unknown analysis worker export format');
      const bytes = new TextEncoder().encode(text);
      reply('result', { value: bytes }, [bytes.buffer]);
    } catch (error) {
      reply('error', { message: error.message });
    }
  };
})();
