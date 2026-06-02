(function () {
  'use strict';

  function setDockActive(href) {
    if (!href) return;
    document.querySelectorAll('[data-km-dock-tab]').forEach(function (el) {
      el.classList.toggle('is-active', el.getAttribute('data-km-dock-tab') === href);
    });
  }

  /**
   * Switch device workbench tab panes (no duplicate Bootstrap tab bar).
   * @param {string} href - e.g. "#tab8"
   * @param {string|boolean} labelOrScroll - label for output pane, or false to skip scroll
   */
  function kmShowDeviceTab(href, labelOrScroll) {
    if (!href || href.charAt(0) !== '#') return;
    var pane = document.querySelector(href);
    if (!pane || !pane.classList.contains('tab-pane')) return;

    var container = pane.closest('.tab-content');
    if (container) {
      container.querySelectorAll('.tab-pane').forEach(function (p) {
        p.classList.remove('active');
      });
      pane.classList.add('active');
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
    document.querySelectorAll('[data-km-export-toggle]').forEach(function (btn) {
      var drawer = document.getElementById('km-export-drawer');
      if (!drawer) return;
      btn.addEventListener('click', function () {
        var open = drawer.classList.toggle('open');
        drawer.hidden = !open;
        btn.setAttribute('aria-expanded', String(open));
      });
    });

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
    }

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