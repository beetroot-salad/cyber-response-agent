
(function () {
  var stream = document.querySelector('.tx-stream');
  if (stream) {
    var entries = [].slice.call(stream.querySelectorAll('.tx-entry'));
    var txGroups = [].slice.call(stream.querySelectorAll('.tx-group'));
    var search = document.querySelector('.tx-search');
    var typeSel = document.querySelector('.tx-type');
    var errToggle = document.querySelector('.tx-errors');
    var chips = [].slice.call(document.querySelectorAll('.tx-chip'));
    var clearBtn = document.querySelector('.tx-clear');
    var noRes = document.querySelector('.tx-noresults');
    var activeTool = null;
    function apply() {
      var q = (search && search.value || '').toLowerCase().trim();
      var ty = typeSel ? typeSel.value : '';
      var errOnly = errToggle ? errToggle.checked : false;
      var shown = 0;
      entries.forEach(function (el) {
        var ok = true;
        if (ty && el.dataset.kind !== ty) ok = false;
        if (ok && errOnly && el.dataset.kind !== 'retry') ok = false;
        if (ok && activeTool) {
          var t = el.dataset.tool, ts = (el.dataset.tools || '').split(' ');
          if (t !== activeTool && ts.indexOf(activeTool) < 0) ok = false;
        }
        if (ok && q && el.textContent.toLowerCase().indexOf(q) < 0) ok = false;
        el.hidden = !ok;
        if (ok) shown++;
      });
      // Collapse a phase group whose every entry was filtered out.
      txGroups.forEach(function (g) {
        g.hidden = g.querySelectorAll('.tx-entry:not([hidden])').length === 0;
      });
      if (noRes) noRes.hidden = shown > 0;
    }
    if (search) search.addEventListener('input', apply);
    if (typeSel) typeSel.addEventListener('change', apply);
    if (errToggle) errToggle.addEventListener('change', apply);
    chips.forEach(function (c) {
      c.addEventListener('click', function () {
        var t = c.dataset.tool;
        if (activeTool === t) { activeTool = null; c.classList.remove('chip-active'); }
        else { activeTool = t; chips.forEach(function (x) { x.classList.toggle('chip-active', x === c); }); }
        apply();
      });
    });
    if (clearBtn) clearBtn.addEventListener('click', function () {
      if (search) search.value = '';
      if (typeSel) typeSel.value = '';
      if (errToggle) errToggle.checked = false;
      activeTool = null;
      chips.forEach(function (x) { x.classList.remove('chip-active'); });
      apply();
    });
    // Phase scroll-spy: highlight the sidebar link of the phase in view.
    var navLinks = [].slice.call(document.querySelectorAll('.phase-nav a'));
    var byPhase = {};
    navLinks.forEach(function (a) { byPhase[a.getAttribute('data-phase-link')] = a; });
    var markers = txGroups.filter(function (e) { return e.id && e.id.indexOf('tx-') === 0; });
    if ('IntersectionObserver' in window && markers.length) {
      var obs = new IntersectionObserver(function (es) {
        es.forEach(function (en) {
          if (en.isIntersecting) {
            var a = byPhase[en.target.dataset.phase];
            if (a) { navLinks.forEach(function (x) { x.classList.remove('pn-active'); }); a.classList.add('pn-active'); }
          }
        });
      }, { rootMargin: '-90px 0px -70% 0px' });
      markers.forEach(function (m) { obs.observe(m); });
    }
  }
  // Lead goals (in the analysis fold): only the ones actually truncated by the
  // one-line clamp become click-to-expand — a short goal that fits stays inert.
  [].slice.call(document.querySelectorAll('.lead-mini-goal')).forEach(function (g) {
    if (g.scrollWidth <= g.clientWidth) return;  // fits on its line — nothing to expand
    g.classList.add('clip');
    g.title = 'click to expand';
    g.addEventListener('click', function () {
      g.parentNode.classList.toggle('expanded');
    });
  });
  // A drop-down nav link sits inside its <summary>, so a plain click would both
  // navigate and toggle the drop-down. Suppress the toggle and jump manually, so
  // clicking the section label goes to the section without collapsing its list.
  [].slice.call(document.querySelectorAll('.toc-dd-link')).forEach(function (a) {
    a.addEventListener('click', function (e) {
      e.preventDefault();
      location.hash = a.getAttribute('href');
    });
  });
})();
