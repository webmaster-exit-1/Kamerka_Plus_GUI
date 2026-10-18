(function () {
  'use strict';

  function initNavigation() {
    var sidebar = document.getElementById('km-navigation');
    var toggle = document.getElementById('km-nav-toggle');
    var backdrop = document.querySelector('.km-nav-backdrop');
    var content = document.querySelector('.page-content');
    if (!sidebar || !toggle || !backdrop || !content) return;
    var mobile = window.matchMedia('(max-width: 1000px)');
    var open = false;
    document.documentElement.classList.add('km-js');

    function setOpen(next, restoreFocus) {
      open = next && mobile.matches;
      document.body.classList.toggle('km-nav-open', open);
      backdrop.hidden = !open;
      toggle.setAttribute('aria-expanded', String(open));
      content.inert = open;
      if (open) {
        sidebar.querySelector('[data-km-nav-close]').focus();
      } else if (restoreFocus) {
        toggle.focus();
      }
    }

    toggle.addEventListener('click', function () { setOpen(!open, false); });
    document.querySelectorAll('[data-km-nav-close]').forEach(function (button) {
      button.addEventListener('click', function () { setOpen(false, true); });
    });
    sidebar.addEventListener('click', function (event) {
      if (open && event.target.closest('a')) setOpen(false, true);
    });
    document.addEventListener('keydown', function (event) {
      if (!open) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        setOpen(false, true);
      } else if (event.key === 'Tab') {
        var items = Array.from(sidebar.querySelectorAll('a[href], button:not([disabled]), [tabindex="0"]'))
          .filter(function (item) { return item.getClientRects().length && item.getAttribute('aria-disabled') !== 'true'; });
        var first = items[0];
        var last = items[items.length - 1];
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    });
    mobile.addEventListener('change', function () { setOpen(false, false); });
  }

  function initWorkerStatus() {
    var panel = document.querySelector('[data-worker-url]');
    if (!panel) return;
    var status = document.getElementById('km-worker-status');
    var fields = ['active', 'reserved', 'queue'];
    var timer;
    var pending = false;

    function update(data) {
      fields.forEach(function (field) {
        var key = field === 'queue' ? 'queue_depth' : field + '_tasks';
        var value = data && data[key];
        document.getElementById('worker-' + field).textContent =
          typeof value === 'number' && Number.isFinite(value) ? value : '—';
      });
      var connected = data && Array.isArray(data.workers) && data.workers.length > 0;
      status.textContent = !data ? 'Telemetry unavailable' : connected ? 'Workers connected' : 'No workers connected';
      status.dataset.state = connected ? 'online' : 'offline';
    }

    function refresh() {
      window.clearTimeout(timer);
      if (document.hidden || pending) return;
      pending = true;
      var controller = new AbortController();
      var timeout = window.setTimeout(function () { controller.abort(); }, 8000);
      fetch(panel.dataset.workerUrl, {credentials: 'same-origin', signal: controller.signal})
        .then(function (response) {
          if (!response.ok) throw new Error('Worker status unavailable');
          return response.json();
        })
        .then(update)
        .catch(function () { update(null); })
        .finally(function () {
          window.clearTimeout(timeout);
          pending = false;
          if (!document.hidden) timer = window.setTimeout(refresh, 30000);
        });
    }
    document.addEventListener('visibilitychange', refresh);
    refresh();
  }

  function setDockActive(href) {
    if (!href) return;
    document.querySelectorAll('[data-km-dock-tab]').forEach(function (el) {
      var active = el.getAttribute('data-km-dock-tab') === href;
      el.classList.toggle('is-active', active);
      el.setAttribute('aria-pressed', String(active));
    });
  }

  /**
   * Switch device workbench tab panes (no duplicate Bootstrap tab bar).
   * @param {string} href - e.g. "#tab8"
   * @param {string|boolean} labelOrScroll - label for output pane, or false to skip scroll
   */
  function kmShowDeviceTab(href, labelOrScroll) {
    if (!href || href.charAt(0) !== '#') return;
    var pane = document.getElementById(href.slice(1));
    if (!pane || !pane.closest('.km-device-tab-content') || !pane.classList.contains('tab-pane')) return;

    var container = pane.closest('.tab-content');
    if (container) {
      container.querySelectorAll('.tab-pane').forEach(function (p) {
        p.classList.remove('active');
      });
      pane.classList.add('active');
      // Existing map tabs listen for Bootstrap's shown event to recalculate their size.
      if (window.jQuery) window.jQuery(pane).trigger('shown.bs.tab');
      window.dispatchEvent(new Event('resize'));
    }

    setDockActive(href);

    if (labelOrScroll !== false) {
      if (labelOrScroll && typeof labelOrScroll === 'string') {
        var out = document.getElementById('km-tool-output');
        if (out) out.textContent = 'Viewing: ' + labelOrScroll;
      }
      window.scrollTo(0, 0);
    }

    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, null, href);
    }
  }

  window.kmShowDeviceTab = kmShowDeviceTab;

  document.addEventListener('DOMContentLoaded', function () {
    initNavigation();
    initWorkerStatus();

    var exportButtons = document.querySelectorAll('[data-km-export-toggle]');
    var exportDrawer = document.getElementById('km-export-drawer');
    function setExportOpen(open) {
      exportDrawer.classList.toggle('open', open);
      exportDrawer.hidden = !open;
      exportButtons.forEach(function (button) { button.setAttribute('aria-expanded', String(open)); });
    }
    document.querySelectorAll('[data-km-export-toggle]').forEach(function (btn) {
      if (!exportDrawer) return;
      btn.addEventListener('click', function () {
        setExportOpen(exportDrawer.hidden);
      });
    });
    if (exportDrawer) {
      setExportOpen(false);
      document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape' && !exportDrawer.hidden) {
          setExportOpen(false);
          if (exportButtons.length) exportButtons[0].focus();
        }
      });
    }

    document.querySelectorAll('[data-km-dock-tab]').forEach(function (el) {
      el.addEventListener('click', function (e) {
        var href = el.getAttribute('data-km-dock-tab');
        if (!href) return;
        e.preventDefault();
        kmShowDeviceTab(href, (el.textContent || '').trim());
      });
    });

    var initial = document.querySelector('.km-device-tab-content .tab-pane.active');
    if (initial && initial.id) {
      setDockActive('#' + initial.id);
      kmShowDeviceTab(window.location.hash, false);
    }
    window.addEventListener('hashchange', function () { kmShowDeviceTab(window.location.hash, false); });

    var output = document.getElementById('km-tool-output');
    if (output && typeof window.jQuery !== 'undefined') {
      window.jQuery(document).ajaxComplete(function (_e, xhr, settings) {
        if (!settings || !settings.url) return;
        if (settings.url.indexOf('/get-task-info') !== -1) return;
        var line = settings.type + ' ' + settings.url;
        if (xhr.status >= 400) {
          line += ' → error ' + xhr.status;
        } else {
          line += ' → ok';
        }
        var ts = new Date().toLocaleTimeString();
        output.textContent = '[' + ts + '] ' + line + '\n' + (output.textContent || '');
        if (output.textContent.length > 8000) {
          output.textContent = output.textContent.slice(0, 8000);
        }
      });
    }
  });
})();