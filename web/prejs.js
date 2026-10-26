// Mount an IndexedDB-backed /save directory before main() so saves, settings and high scores persist.
// An online guest instead plays from a copy of the host's save files, kept in memory (the page writes them in
// before the game starts), so its own saves are left untouched.
Module.preRun = Module.preRun || [];
Module.preRun.push(function () {
  FS.mkdir('/save');
  if (Module.netGuest) return;
  FS.mount(IDBFS, {}, '/save');
  addRunDependency('idbfs-load');
  FS.syncfs(true, function (err) {
    if (err) console.warn('could not load saves', err);
    removeRunDependency('idbfs-load');
  });
});

// PORT_* switches (src/*.c getenv) from the page address, e.g. ?PORT_CLEAR_FRAMES=1 or ?PORT_DDLOG=1
Module.preRun.push(function () {
  new URLSearchParams(location.search).forEach(function (v, k) { if (/^PORT_[A-Z_]+$/.test(k)) ENV[k] = v; });
});
