(function () {
  'use strict';

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

    function setDockActive(href) {
      if (!href) return;
      document.querySelectorAll('[data-km-dock-tab]').forEach(function (el) {
        el.classList.toggle('is-active', el.getAttribute('data-km-dock-tab') === href);
      });
    }

    function showDockTab(href, label) {
      if (!href) return;
      var tab = document.querySelector('.nav-tabs a[href="' + href + '"]');
      if (tab && typeof window.jQuery !== 'undefined') {
        window.jQuery(tab).tab('show');
      }
      setDockActive(href);
      window.scrollTo(0, 0);
      var out = document.getElementById('km-tool-output');
      if (out && label) {
        out.textContent = 'Viewing: ' + label;
      }
    }

    document.querySelectorAll('[data-km-dock-tab]').forEach(function (el) {
      el.addEventListener('click', function (e) {
        var href = el.getAttribute('data-km-dock-tab');
        if (!href) return;
        e.preventDefault();
        showDockTab(href, (el.textContent || '').trim());
      });
    });

    if (typeof window.jQuery !== 'undefined') {
      window.jQuery('a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
        var href = e.target && e.target.getAttribute('href');
        setDockActive(href);
      });
      var initial = document.querySelector('.nav-tabs li.active > a[data-toggle="tab"]');
      if (initial) {
        setDockActive(initial.getAttribute('href'));
      }
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