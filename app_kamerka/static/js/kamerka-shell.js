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

    document.querySelectorAll('[data-km-dock-tab]').forEach(function (el) {
      el.addEventListener('click', function (e) {
        var href = el.getAttribute('data-km-dock-tab');
        if (!href) return;
        var tab = document.querySelector('[href="' + href + '"]');
        if (tab && typeof window.jQuery !== 'undefined') {
          e.preventDefault();
          window.jQuery(tab).tab('show');
          window.scrollTo(0, 0);
          var pane = document.querySelector(href);
          if (pane) {
            var out = document.getElementById('km-tool-output');
            if (out) {
              out.textContent = 'Viewing: ' + (el.textContent || '').trim();
            }
          }
        }
      });
    });

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