/**
 * map_themes.js  –  Leaflet tile-layer theme switcher for Kamerka Plus
 * =====================================================================
 * Provides 5 map themes.  Each theme ships a primary tile-layer URL and
 * an offline canvas fallback that renders without any external requests.
 *
 * Usage (called once after L.map() is created):
 *
 *   var currentTileLayer = KamerkaTiles.apply('cyberpunk', map);
 *
 * Switching themes at runtime:
 *
 *   currentTileLayer = KamerkaTiles.switch('matrix', map, currentTileLayer);
 *
 * Injecting the floating picker into a panel heading:
 *
 *   KamerkaTiles.injectPicker(map, '#my-heading-selector');
 */

var KamerkaTiles = (function () {
    'use strict';

    // ── Offline canvas fallback ─────────────────────────────────────────────
    /**
     * Build a Leaflet GridLayer whose tiles are drawn on <canvas> using the
     * given background colour and grid line colour.  Zero external requests.
     */
    function _canvasLayer(bgColour, gridColour, lineOpacity) {
        return L.GridLayer.extend({
            createTile: function () {
                var canvas = document.createElement('canvas');
                canvas.width = canvas.height = 256;
                var ctx = canvas.getContext('2d', { willReadFrequently: true });
                ctx.fillStyle = bgColour;
                ctx.fillRect(0, 0, 256, 256);
                ctx.strokeStyle = gridColour;
                ctx.globalAlpha = lineOpacity || 0.15;
                ctx.lineWidth = 0.5;
                for (var i = 0; i <= 256; i += 32) {
                    ctx.beginPath(); ctx.moveTo(i, 0); ctx.lineTo(i, 256); ctx.stroke();
                    ctx.beginPath(); ctx.moveTo(0, i); ctx.lineTo(256, i); ctx.stroke();
                }
                return canvas;
            }
        });
    }

    // ── Theme registry ──────────────────────────────────────────────────────
    var THEMES = {
        cyberpunk: {
            label: '🌐 Cyberpunk',
            // CartoDB Dark Matter — deep black city map
            url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
            attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
            maxZoom: 19,
            subdomains: 'abcd',
            fallbackBg: '#0a0d12',
            fallbackGrid: '#0064d7',
            cssFilter: '',
        },
        matrix: {
            label: '💚 Matrix',
            // CartoDB Dark Matter + CSS green tint
            url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
            attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
            maxZoom: 19,
            subdomains: 'abcd',
            fallbackBg: '#000800',
            fallbackGrid: '#00ff44',
            // green tint applied via CSS on the tile pane
            cssFilter: 'sepia(1) saturate(4) hue-rotate(85deg) brightness(0.7)',
        },
        thermal: {
            label: '🔥 Thermal',
            // CartoDB Dark Matter + purple/red tint
            url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
            attribution: '&copy; <a href="https://carto.com/">CARTO</a>',
            maxZoom: 19,
            subdomains: 'abcd',
            fallbackBg: '#05000a',
            fallbackGrid: '#ff6600',
            cssFilter: 'sepia(1) saturate(5) hue-rotate(300deg) brightness(0.6)',
        },
        satellite: {
            label: '🛰 Satellite',
            // ESRI World Imagery
            url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
            attribution: '&copy; <a href="https://www.esri.com/">Esri</a>',
            maxZoom: 18,
            subdomains: '',
            fallbackBg: '#0d1a2e',
            fallbackGrid: '#ffffff',
            cssFilter: '',
        },
        toner: {
            label: '🗺 Toner',
            // Stadia Stamen Toner (high-contrast black & white)
            url: 'https://tiles.stadiamaps.com/tiles/stamen_toner/{z}/{x}/{y}{r}.png',
            attribution: '&copy; <a href="https://stadiamaps.com/">Stadia</a>',
            maxZoom: 20,
            subdomains: '',
            fallbackBg: '#111111',
            fallbackGrid: '#ffffff',
            cssFilter: 'invert(1) brightness(0.6)',
        },
    };

    // Ordered list for the picker UI
    var THEME_ORDER = ['cyberpunk', 'matrix', 'thermal', 'satellite', 'toner'];

    // Key stored in localStorage so the choice survives page reloads
    var STORAGE_KEY = 'kamerka_map_theme';

    // ── Internal helpers ────────────────────────────────────────────────────

    function _buildLayer(themeKey) {
        var t = THEMES[themeKey];
        if (!t) { t = THEMES.cyberpunk; }

        // Canvas layer is added immediately so the map always looks good offline.
        var CanvasClass = _canvasLayer(t.fallbackBg, t.fallbackGrid, 0.15);
        var canvasFallback = new CanvasClass();

        // Apply CSS colour filter for tinted themes.
        function _applyFilter(map) {
            var pane = map && map.getPanes && map.getPanes().tilePane;
            if (pane && t.cssFilter) {
                pane.style.filter = t.cssFilter;
                pane.style.webkitFilter = t.cssFilter;
            }
        }

        // Probe reachability; replace canvas with real tiles only if reachable.
        var probeUrl = t.url
            .replace('{s}', (t.subdomains || 'a')[0] || 'a')
            .replace('{z}', '1').replace('{x}', '0').replace('{y}', '0')
            .replace('{r}', '');

        var img = new Image();
        img.onload = function () {
            // Tile server reachable — swap canvas for the real tile layer.
            if (canvasFallback._map) {
                var map = canvasFallback._map;
                map.removeLayer(canvasFallback);
                var tileLayer = L.tileLayer(t.url, {
                    attribution: t.attribution,
                    maxZoom: t.maxZoom || 19,
                    subdomains: t.subdomains || 'abc',
                    errorTileUrl: 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7',
                });
                tileLayer.on('add', function () { _applyFilter(tileLayer._map); });
                tileLayer.on('remove', function () {
                    var pane = tileLayer._map && tileLayer._map.getPanes().tilePane;
                    if (pane) { pane.style.filter = ''; pane.style.webkitFilter = ''; }
                });
                tileLayer.addTo(map);
            }
        };
        // onerror: do nothing — canvas stays in place.
        img.onerror = function () {};
        img.src = probeUrl;

        return canvasFallback;
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /**
     * Apply *themeKey* to *map*, returning the new tile layer.
     * Persists the choice to localStorage.
     */
    function apply(themeKey, map) {
        var layer = _buildLayer(themeKey);
        layer.addTo(map);
        try { localStorage.setItem(STORAGE_KEY, themeKey); } catch (e) {}
        return layer;
    }

    /**
     * Remove *currentLayer* from *map* and apply *themeKey*.
     * Returns the new tile layer.
     */
    function switchTheme(themeKey, map, currentLayer) {
        if (currentLayer && map.hasLayer(currentLayer)) {
            map.removeLayer(currentLayer);
        }
        return apply(themeKey, map);
    }

    /**
     * Return the last theme key saved to localStorage (or 'cyberpunk').
     */
    function savedTheme() {
        try {
            var k = localStorage.getItem(STORAGE_KEY);
            return (k && THEMES[k]) ? k : 'cyberpunk';
        } catch (e) { return 'cyberpunk'; }
    }

    /**
     * Inject a floating theme picker panel into *headingSelector* inside the
     * map panel, wired to *map*.  *currentLayerRef* is an object with a
     * ``layer`` property so the reference can be mutated across closures.
     *
     *   var ref = { layer: currentTileLayer };
     *   KamerkaTiles.injectPicker(map, ref, '.panel-heading');
     */
    function injectPicker(map, layerRef, headingSelector) {
        // Build picker HTML
        var html = '<div class="cp-map-theme-picker" style="' +
            'position:absolute;top:8px;right:8px;z-index:1000;' +
            'background:rgba(10,13,18,0.88);border:1px solid #0064d7;padding:4px 6px;' +
            'font-family:var(--cp-font,monospace);font-size:0.62em;letter-spacing:0.06em;">' +
            '<span style="color:#3a4555;display:block;margin-bottom:3px;">MAP THEME</span>';

        THEME_ORDER.forEach(function (key) {
            var t = THEMES[key];
            html += '<button data-theme="' + key + '" style="' +
                'display:block;width:100%;text-align:left;margin:2px 0;' +
                'background:transparent;border:1px solid transparent;' +
                'color:#00e1ff;cursor:pointer;padding:2px 4px;' +
                'font-family:inherit;font-size:inherit;letter-spacing:inherit;' +
                '" onmouseover="this.style.borderColor=\'#0064d7\'" ' +
                'onmouseout="this.style.borderColor=\'transparent\'">' +
                t.label + '</button>';
        });
        html += '</div>';

        // Insert after the map container
        var mapContainer = document.getElementById('leaflet_world_map');
        if (mapContainer) {
            mapContainer.style.position = 'relative';
            mapContainer.insertAdjacentHTML('beforeend', html);

            mapContainer.querySelectorAll('.cp-map-theme-picker button').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    var key = btn.getAttribute('data-theme');
                    layerRef.layer = switchTheme(key, map, layerRef.layer);
                    // Highlight active button
                    mapContainer.querySelectorAll('.cp-map-theme-picker button').forEach(function (b) {
                        b.style.color = '#00e1ff';
                        b.style.fontWeight = 'normal';
                    });
                    btn.style.color = '#ff00cd';
                    btn.style.fontWeight = 'bold';
                });
            });

            // Highlight the currently active theme button
            var active = mapContainer.querySelector('[data-theme="' + layerRef.currentKey + '"]');
            if (active) {
                active.style.color = '#ff00cd';
                active.style.fontWeight = 'bold';
            }
        }
    }

    return {
        themes: THEMES,
        apply: apply,
        switch: switchTheme,
        savedTheme: savedTheme,
        injectPicker: injectPicker,
    };
}());
