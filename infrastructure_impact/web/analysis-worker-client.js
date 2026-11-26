/* The immutable client and its worker live in the same publication assets directory. */
(() => {
  const script = document.currentScript,
    name = script?.dataset.analysisWorker,
    url = /^[a-f0-9]{64}\.js$/.test(name) && new URL(name, script.src);
  function create(identity, load, operation, maximum) {
    if (!url || url.origin !== location.origin)
      throw Error('Invalid analysis worker asset binding');
    const generation = JSON.stringify([identity.publication?.id, identity.generated_at]),
      queue = [];
    let worker,
      pending,
      retained,
      draining = false,
      disposed = false,
      idleTimer,
      sequence = 0;

    function stop(error) {
      clearTimeout(idleTimer);
      const active = pending;
      pending = null;
      retained = null;
      const previous = worker;
      worker = null;
      previous?.terminate();
      active?.reject(error);
    }
    function start() {
      if (worker) return;
      const instance = new Worker(url);
      worker = instance;
      const fault = (error) => {
        if (instance === worker) stop(error);
      };
      instance.onerror = (event) =>
        fault(Error(event.message || 'Analysis worker runtime failure'));
      instance.onmessageerror = () => fault(Error('Invalid analysis worker message'));
      instance.onmessage = async ({ data }) => {
        if (instance !== worker) return;
        const rpc = pending;
        try {
          if (!rpc || data?.generation !== generation || data.id !== rpc.id || data.key !== rpc.key)
            throw Error('Analysis worker reply generation or request differs');
          if (data.type === 'load') {
            if (!rpc.view || rpc.loading || data.index !== rpc.next || !rpc.view.chunks[data.index])
              throw Error('Unexpected analysis worker part request');
            rpc.loading = true;
            const part = rpc.view.chunks[rpc.next++].part,
              bytes = await load(part, rpc.owner);
            if (instance !== worker || pending !== rpc) return;
            const owned = bytes.slice();
            rpc.loading = false;
            instance.postMessage(
              {
                id: rpc.id,
                key: rpc.key,
                generation,
                type: 'chunk',
                index: data.index,
                bytes: owned,
              },
              [owned.buffer],
            );
            return;
          }
          if (data.type === 'error') {
            pending = null;
            rpc.reject(Error(data.message || 'Analysis worker operation failed'));
            return;
          }
          if (
            data.type !== rpc.expect ||
            rpc.loading ||
            (rpc.view && rpc.next !== rpc.view.chunks.length)
          )
            throw Error('Invalid analysis worker reply');
          pending = null;
          rpc.resolve(data.value);
        } catch (error) {
          fault(error);
        }
      };
    }
    function call(group, type, fields) {
      start();
      const id = ++sequence,
        key = group.key;
      return group.owner.run(
        new Promise((resolve, reject) => {
          pending = {
            id,
            key,
            owner: group.owner,
            view: fields.view,
            next: 0,
            expect: type === 'prepare' ? 'ready' : 'result',
            resolve,
            reject,
          };
          try {
            worker.postMessage({ id, key, generation, type, ...fields });
          } catch (error) {
            stop(error);
          }
        }),
      );
    }
    async function drain() {
      if (draining) return;
      draining = true;
      try {
        while (queue.length) {
          const group = queue[0];
          try {
            const first = group.callers.values().next().value;
            if (!first) continue;
            if (retained !== group.key) {
              retained = null;
              await call(group, 'prepare', { view: group.view, study: first.study, max: maximum });
              retained = group.key;
            }
            for (const caller of group.callers) {
              try {
                const value = await call(group, 'deliver', {
                  study: caller.study,
                  format: caller.format,
                  max: caller.max,
                });
                caller.resolve(value);
              } catch (error) {
                caller.reject(error);
                if (!worker || group.owner.signal.aborted) throw error;
              } finally {
                group.callers.delete(caller);
              }
            }
          } catch (error) {
            stop(error);
            for (const caller of group.callers) caller.reject(error);
          } finally {
            group.callers.clear();
            group.owner.close();
            queue.shift();
          }
        }
      } finally {
        draining = false;
        if (worker) idleTimer = setTimeout(() => stop(), 60000);
      }
    }
    async function request(view, study, format, max, op) {
      if (disposed) throw Error('Analysis worker disposed');
      await op.run(Promise.resolve());
      if (disposed) throw Error('Analysis worker disposed');
      clearTimeout(idleTimer);
      const key = view.decoded.sha256;
      let group = queue.at(-1);
      if (!group || group.key !== key || group.owner.signal.aborted) {
        group = { key, view, owner: operation(), callers: new Set() };
        queue.push(group);
      }
      let caller;
      const result = new Promise((resolve, reject) => {
        caller = { study, format, max, resolve, reject };
        group.callers.add(caller);
      });
      void drain();
      try {
        return await op.run(result);
      } finally {
        if (group.callers.delete(caller) && !group.callers.size) {
          group.owner.close();
          if (group === queue[0]) stop(Error('Analysis worker cancelled'));
        }
      }
    }
    function dispose() {
      disposed = true;
      const error = Error('Analysis worker disposed');
      stop(error);
      for (const group of queue) {
        group.owner.close();
        for (const caller of group.callers) caller.reject(error);
        group.callers.clear();
      }
    }
    return { request, dispose };
  }
  window.InfrastructureAnalysisWorker = { create };
})();
