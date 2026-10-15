// Keep an open tab current without discarding questions or unfinished forms.
(function () {
  var busy = false;
  var lastCompleted = null;
  var versionMeta = document.querySelector('meta[name="app-version"]');
  var loadedVersion = versionMeta && versionMeta.content;
  function tick() {
    if (busy || document.hidden || monitorRefreshing) return Promise.resolve();
    busy = true;
    return Promise.all([
      api('/api/version').then(function (data) {
        if (loadedVersion && data.web_version !== loadedVersion) $('update-notice').hidden = false;
      }).catch(function () {}),
      loadMonitorStatus(true).then(function (data) {
        if (!data) return;
        var completed = data.last_run || '';
        // The initial view already loads its data. Subsequent completion events
        // remain pending until the visible view actually refreshes successfully.
        if (lastCompleted === null) lastCompleted = completed;
        var changed = completed !== lastCompleted;
        if ($('settings') && !$('settings').hidden) loadModelReviewStatus();
        if (changed && !data.running) {
          var refresh;
          if (!$('overview').hidden) refresh = loadOverview();
          // Refresh the feed only; never replace an open detail or form.
          else if (!$('monitor').hidden) refresh = loadItems('monitor');
          else {
            // These views load current data when the user navigates to them.
            lastCompleted = completed;
            return;
          }
          return Promise.resolve(refresh).then(function (result) {
            // loadOverview reports handled failures as false; the feed can
            // return null if a manual refresh takes ownership while fetching.
            if (result !== false && result !== null) lastCompleted = completed;
          });
        }
      }).catch(function () {})
    ]).then(function () { busy = false; });
  }
  on('reload-page', 'click', function () { window.location.reload(); });
  document.addEventListener('visibilitychange', function () { if (!document.hidden) tick(); });
  window.addEventListener('focus', tick);
  setInterval(tick, 15000);
  tick();
})();
