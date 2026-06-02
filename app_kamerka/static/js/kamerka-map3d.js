/**
 * Kamerka 3D map — MapLibre GL JS (default: OpenFreeMap, no API key).
 * Optional MAPBOX_ACCESS_TOKEN enables Mapbox dark-v11 + richer building mesh.
 */
(function (global) {
    'use strict';

    var OPENFREEMAP_STYLE = 'https://tiles.openfreemap.org/styles/dark';
    var MAPBOX_STYLE = 'mapbox://styles/mapbox/dark-v11';

    var SEVERITY_COLOR = {
        info: '#0064d7',
        low: '#00e1ff',
        medium: '#ffe600',
        high: '#ff7a00',
        critical: '#ff2050',
    };

    function KamerkaMap3D(opts) {
        this.token = (opts.token || '').trim();
        this.searchId = opts.searchId || '';
        this.dataUrl = opts.dataUrl || '/map3d/devices.geojson';
        this.container = opts.container || 'map3d-canvas';
        this.map = null;
        this.gl = null;
        this.basemap = 'openfreemap';
        this.buildingsOn = true;
        this.heatmapOn = true;
        this.columnsOn = false;
    }

    KamerkaMap3D.prototype._dataQuery = function () {
        return this.searchId ? '?search=' + encodeURIComponent(this.searchId) : '';
    };

    KamerkaMap3D.prototype._resolveGl = function () {
        if (typeof maplibregl !== 'undefined') {
            return maplibregl;
        }
        if (typeof mapboxgl !== 'undefined') {
            return mapboxgl;
        }
        return null;
    };

    KamerkaMap3D.prototype._resolveStyle = function () {
        if (this.token) {
            this.basemap = 'mapbox';
            return MAPBOX_STYLE;
        }
        this.basemap = 'openfreemap';
        return OPENFREEMAP_STYLE;
    };

    KamerkaMap3D.prototype._setBasemapNote = function (text) {
        var el = document.getElementById('map3d-basemap');
        if (el) el.textContent = text;
    };

    KamerkaMap3D.prototype.init = function () {
        var self = this;
        this.gl = this._resolveGl();
        if (!this.gl) {
            this._showSetup('MapLibre GL failed to load. Check your network connection.');
            return Promise.reject(new Error('maplibregl not loaded'));
        }

        if (this.token) {
            this.gl.accessToken = this.token;
        }

        var style = this._resolveStyle();
        this._setBasemapNote(
            this.basemap === 'mapbox'
                ? 'Basemap: Mapbox (optional token) · enhanced buildings'
                : 'Basemap: OpenFreeMap · free, no account'
        );

        this.map = new this.gl.Map({
            container: this.container,
            style: style,
            center: [105, 35],
            zoom: 3,
            pitch: 50,
            bearing: -12,
            antialias: true,
        });

        this.map.addControl(new this.gl.NavigationControl({ visualizePitch: true }), 'top-right');
        this.map.addControl(new this.gl.FullscreenControl(), 'top-right');

        return new Promise(function (resolve, reject) {
            self.map.on('load', function () {
                self._hideSetup();
                self._addSky();
                self._loadData()
                    .then(function () {
                        self._wireControls();
                        resolve(self);
                    })
                    .catch(reject);
            });
            self.map.on('error', function (e) {
                console.error('map3d error', e);
            });
            self.map.on('style.load', function () {
                if (self.buildingsOn) {
                    self._addBuildings();
                }
            });
        });
    };

    KamerkaMap3D.prototype._showSetup = function (message) {
        var el = document.getElementById('map3d-setup');
        var msg = document.getElementById('map3d-setup-msg');
        if (msg && message) msg.textContent = message;
        if (el) el.style.display = 'flex';
    };

    KamerkaMap3D.prototype._hideSetup = function () {
        var el = document.getElementById('map3d-setup');
        if (el) el.style.display = 'none';
    };

    KamerkaMap3D.prototype._addSky = function () {
        try {
            if (this.map.getLayer('sky')) return;
            this.map.addLayer({
                id: 'sky',
                type: 'sky',
                paint: {
                    'sky-type': 'atmosphere',
                    'sky-atmosphere-sun': [0.0, 90.0],
                    'sky-atmosphere-sun-intensity': 12,
                },
            });
        } catch (e) {
            /* sky not supported on all styles */
        }
    };

    KamerkaMap3D.prototype._firstSymbolLayerId = function () {
        var layers = this.map.getStyle().layers || [];
        for (var i = 0; i < layers.length; i++) {
            var layer = layers[i];
            if (layer.type === 'symbol' && layer.layout && layer.layout['text-field']) {
                return layer.id;
            }
        }
        return undefined;
    };

    KamerkaMap3D.prototype._addBuildings = function () {
        var map = this.map;
        if (map.getLayer('3d-buildings')) return;

        var before = this._firstSymbolLayerId();
        var layerDef = null;

        if (map.getSource('composite')) {
            layerDef = {
                id: '3d-buildings',
                source: 'composite',
                'source-layer': 'building',
                filter: ['==', 'extrude', 'true'],
                type: 'fill-extrusion',
                minzoom: 14,
                paint: {
                    'fill-extrusion-color': '#1a2744',
                    'fill-extrusion-height': ['get', 'height'],
                    'fill-extrusion-base': ['get', 'min_height'],
                    'fill-extrusion-opacity': 0.65,
                },
            };
        } else if (map.getSource('openmaptiles')) {
            layerDef = {
                id: '3d-buildings',
                source: 'openmaptiles',
                'source-layer': 'building',
                type: 'fill-extrusion',
                minzoom: 13,
                paint: {
                    'fill-extrusion-color': '#1a2744',
                    'fill-extrusion-height': [
                        'coalesce',
                        ['get', 'render_height'],
                        ['get', 'height'],
                        12,
                    ],
                    'fill-extrusion-base': ['coalesce', ['get', 'render_min_height'], 0],
                    'fill-extrusion-opacity': 0.6,
                },
            };
        }

        if (!layerDef) {
            return;
        }

        try {
            if (before) {
                map.addLayer(layerDef, before);
            } else {
                map.addLayer(layerDef);
            }
        } catch (e) {
            console.warn('3d-buildings layer skipped', e);
        }
    };

    KamerkaMap3D.prototype._loadData = function () {
        var self = this;
        var url = this.dataUrl + this._dataQuery();
        return fetch(url)
            .then(function (r) { return r.json(); })
            .then(function (fc) {
                if (self.map.getSource('devices')) {
                    self.map.getSource('devices').setData(fc);
                } else {
                    self.map.addSource('devices', { type: 'geojson', data: fc });
                    self._addDeviceLayers();
                }
                self._fitBounds(fc);
                self._updateCount(fc.features ? fc.features.length : 0);
                return fc;
            });
    };

    KamerkaMap3D.prototype._addDeviceLayers = function () {
        var map = this.map;
        var gl = this.gl;

        map.addLayer({
            id: 'devices-heat',
            type: 'heatmap',
            source: 'devices',
            maxzoom: 16,
            paint: {
                'heatmap-weight': ['get', 'weight'],
                'heatmap-intensity': ['interpolate', ['linear'], ['zoom'], 0, 0.6, 14, 2.2],
                'heatmap-color': [
                    'interpolate',
                    ['linear'],
                    ['heatmap-density'],
                    0, 'rgba(0,100,215,0)',
                    0.2, '#0064d7',
                    0.45, '#00e1ff',
                    0.65, '#ff00cd',
                    0.85, '#ff7a00',
                    1, '#ff2050',
                ],
                'heatmap-radius': ['interpolate', ['linear'], ['zoom'], 0, 8, 10, 28, 16, 48],
                'heatmap-opacity': [
                    'interpolate',
                    ['linear'],
                    ['zoom'],
                    8,
                    0.9,
                    14,
                    0,
                ],
            },
        });

        map.addLayer({
            id: 'devices-columns',
            type: 'fill-extrusion',
            source: 'devices',
            minzoom: 11,
            paint: {
                'fill-extrusion-color': [
                    'match',
                    ['get', 'severity'],
                    'critical', SEVERITY_COLOR.critical,
                    'high', SEVERITY_COLOR.high,
                    'medium', SEVERITY_COLOR.medium,
                    'low', SEVERITY_COLOR.low,
                    SEVERITY_COLOR.info,
                ],
                'fill-extrusion-height': [
                    'interpolate',
                    ['linear'],
                    ['get', 'vuln_count'],
                    0, 80,
                    3, 220,
                    10, 520,
                    20, 900,
                ],
                'fill-extrusion-base': 0,
                'fill-extrusion-opacity': 0.88,
            },
            layout: { visibility: 'none' },
        });

        map.addLayer({
            id: 'devices-points',
            type: 'circle',
            source: 'devices',
            minzoom: 2,
            paint: {
                'circle-radius': [
                    'interpolate',
                    ['linear'],
                    ['zoom'],
                    4, 3,
                    12, 7,
                    16, 11,
                ],
                'circle-color': [
                    'match',
                    ['get', 'severity'],
                    'critical', SEVERITY_COLOR.critical,
                    'high', SEVERITY_COLOR.high,
                    'medium', SEVERITY_COLOR.medium,
                    'low', SEVERITY_COLOR.low,
                    SEVERITY_COLOR.info,
                ],
                'circle-stroke-width': 1,
                'circle-stroke-color': '#0a0d12',
                'circle-opacity': [
                    'interpolate',
                    ['linear'],
                    ['zoom'],
                    8,
                    0,
                    14,
                    0.95,
                ],
            },
        });

        map.on('click', 'devices-points', function (e) {
            var p = e.features[0].properties;
            var html =
                '<div class="map3d-popup">' +
                '<b style="color:#00e1ff">' + (p.ip || '') + '</b><br>' +
                (p.type || '') + ' · ' + (p.product || '') + '<br>' +
                'CVEs: ' + (p.vuln_count || 0) + ' · ' + (p.severity || '') + '<br>' +
                '<a href="' + (p.device_url || '#') + '" style="color:#ff00cd">Open workbench</a>' +
                '</div>';
            new gl.Popup({ maxWidth: '280px' })
                .setLngLat(e.lngLat)
                .setHTML(html)
                .addTo(map);
        });
        map.on('mouseenter', 'devices-points', function () { map.getCanvas().style.cursor = 'pointer'; });
        map.on('mouseleave', 'devices-points', function () { map.getCanvas().style.cursor = ''; });

        if (this.buildingsOn) this._addBuildings();
        this._setHeatmap(this.heatmapOn);
        this._setColumns(this.columnsOn);
    };

    KamerkaMap3D.prototype._fitBounds = function (fc) {
        var gl = this.gl;
        var coords = (fc.features || [])
            .map(function (f) { return f.geometry && f.geometry.coordinates; })
            .filter(Boolean);
        if (!coords.length) return;
        var bounds = coords.reduce(
            function (b, c) { return b.extend(c); },
            new gl.LngLatBounds(coords[0], coords[0])
        );
        this.map.fitBounds(bounds, { padding: 60, maxZoom: 12, duration: 1200 });
    };

    KamerkaMap3D.prototype._updateCount = function (n) {
        var el = document.getElementById('map3d-device-count');
        if (el) el.textContent = String(n);
    };

    KamerkaMap3D.prototype._setHeatmap = function (on) {
        this.heatmapOn = on;
        if (!this.map || !this.map.getLayer('devices-heat')) return;
        this.map.setLayoutProperty('devices-heat', 'visibility', on ? 'visible' : 'none');
        if (!this.columnsOn) {
            this.map.setLayoutProperty('devices-points', 'visibility', 'visible');
        }
    };

    KamerkaMap3D.prototype._setColumns = function (on) {
        this.columnsOn = on;
        if (!this.map || !this.map.getLayer('devices-columns')) return;
        this.map.setLayoutProperty('devices-columns', 'visibility', on ? 'visible' : 'none');
        if (on) {
            this.map.setLayoutProperty('devices-heat', 'visibility', 'none');
            this.map.setLayoutProperty('devices-points', 'visibility', 'none');
        } else {
            this._setHeatmap(this.heatmapOn);
        }
    };

    KamerkaMap3D.prototype._setBuildings = function (on) {
        this.buildingsOn = on;
        if (!this.map) return;
        if (on && !this.map.getLayer('3d-buildings')) {
            this._addBuildings();
        } else if (this.map.getLayer('3d-buildings')) {
            this.map.setLayoutProperty('3d-buildings', 'visibility', on ? 'visible' : 'none');
        }
    };

    KamerkaMap3D.prototype._wireControls = function () {
        var self = this;
        function bind(id, fn) {
            var el = document.getElementById(id);
            if (el) el.addEventListener('click', fn);
        }
        bind('map3d-toggle-heat', function () {
            self.heatmapOn = !self.heatmapOn;
            self.columnsOn = false;
            self._setColumns(false);
            self._setHeatmap(self.heatmapOn);
        });
        bind('map3d-toggle-columns', function () {
            self.columnsOn = !self.columnsOn;
            self._setColumns(self.columnsOn);
        });
        bind('map3d-toggle-buildings', function () {
            self.buildingsOn = !self.buildingsOn;
            self._setBuildings(self.buildingsOn);
        });
        bind('map3d-reset-view', function () {
            self.map.flyTo({ center: [105, 35], zoom: 3, pitch: 50, bearing: -12, duration: 1400 });
        });
        bind('map3d-reload', function () {
            self._loadData();
        });
    };

    global.KamerkaMap3D = KamerkaMap3D;
})(typeof window !== 'undefined' ? window : this);