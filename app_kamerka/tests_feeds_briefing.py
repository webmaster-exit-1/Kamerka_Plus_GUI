"""Feeds basemap configuration, response headers and client failure handling."""

import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
from unittest import skipUnless
from unittest.mock import patch

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.middleware.security import SecurityMiddleware
from django.template.loader import render_to_string
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings

from app_kamerka.middleware import SecurityHeadersMiddleware


class FeedMapSettingsTests(SimpleTestCase):
    def load_settings(self, env):
        with patch.dict(os.environ, env, clear=True), patch("dotenv.load_dotenv"):
            return runpy.run_path(str(Path(settings.BASE_DIR) / "kamerka/settings.py"))

    def test_osm_default_has_canonical_https_url_and_linked_attribution(self):
        config = self.load_settings({})
        self.assertEqual(config["FEED_MAP_TILE_URL"], "https://tile.openstreetmap.org/{z}/{x}/{y}.png")
        self.assertIn('href="https://www.openstreetmap.org/copyright"', config["FEED_MAP_TILE_ATTRIBUTION"])

    def test_custom_provider_requires_https_and_attribution(self):
        for env in (
            {"FEED_MAP_TILE_URL": "http://tiles.example/{z}/{x}/{y}.png", "FEED_MAP_TILE_ATTRIBUTION": "Provider"},
            {"FEED_MAP_TILE_URL": "https://tiles.example/{z}/{x}/{y}.png"},
        ):
            with self.subTest(env=env), self.assertRaises(ImproperlyConfigured):
                self.load_settings(env)
        config = self.load_settings({
            "FEED_MAP_TILE_URL": "https://tiles.example/{z}/{x}/{y}.png?key=public",
            "FEED_MAP_TILE_ATTRIBUTION": "Provider",
        })
        self.assertEqual(config["FEED_MAP_TILE_ATTRIBUTION"], "Provider")
        self.assertEqual(self.load_settings({"FEED_MAP_TILE_URL": ""})["FEED_MAP_TILE_URL"], "")


class FeedMapPageTests(TestCase):
    @override_settings(
        FEED_MAP_TILE_URL="https://tiles.example/{z}/{x}/{y}.png?key=public",
        FEED_MAP_TILE_ATTRIBUTION='Provider </script><script>alert("test")</script> & credits',
    )
    def test_page_safely_serializes_configuration_and_preserves_referrer(self):
        response = self.client.get("/feeds-briefing")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Referrer-Policy"], "strict-origin-when-cross-origin")
        self.assertIn("img-src 'self' data: blob: https:", response["Content-Security-Policy"])
        html = response.content.decode()
        serialized = re.search(r'<script id="cp-feed-map-config" type="application/json">(.*?)</script>', html).group(1)
        self.assertNotIn("<script>", serialized)
        self.assertEqual(json.loads(serialized), {
            "url": settings.FEED_MAP_TILE_URL, "attribution": settings.FEED_MAP_TILE_ATTRIBUTION,
        })
        self.assertContains(response, "No mapped cyber feed coverage yet.")

    def test_other_pages_keep_same_origin_policy(self):
        handler = SecurityMiddleware(SecurityHeadersMiddleware(lambda request: HttpResponse()))
        response = handler(RequestFactory().get("/"))
        self.assertEqual(response["Referrer-Policy"], "same-origin")


@skipUnless(shutil.which("node"), "Node is required for the mocked Leaflet runtime test")
class FeedMapRuntimeTests(SimpleTestCase):
    def test_failure_disabled_markers_and_no_data(self):
        javascript = re.findall(
            r"<script>(.*?)</script>",
            render_to_string("feeds_briefing.html", {"feed_map_config": {}}),
            re.S,
        )[-1]
        harness = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
(async function() {
for (const enabled of [true, false]) {
for (const entries of [[], [{geo_lat: 10, geo_lon: 20, title: '<test>', url: 'https://example.com'}]]) {
    const elements = {};
    const timers = [];
    let tileErrors, tileCount = 0, removals = 0, fits = 0, markers = [], views = [];
    let notices = 0;
    const config = {url: enabled ? 'https://tiles.example/{z}/{x}/{y}.png' : '', attribution: 'Provider'};
    const map = {
        setView: function(coords, zoom) { views.push([coords, zoom]); return this; },
        fitBounds: function() { fits++; },
        removeLayer: function(layer) { assert.equal(layer, tiles); removals++; }
    };
    const tiles = {
        on: function(event, handler) { assert.equal(event, 'tileerror'); tileErrors = handler; },
        addTo: function() { return this; }
    };
    const layer = {addTo: function() { return this; }, clearLayers: function() { markers = []; }};
    const context = {
        document: {
            getElementById: function(id) {
                if (!elements[id]) elements[id] = {textContent: '', hidden: true};
                if (id === 'cp-feed-map-config') elements[id].textContent = JSON.stringify(config);
                return elements[id];
            },
            createElement: function() {
                return {set textContent(value) { this.innerHTML = value.replace(/</g, '&lt;'); }};
            }
        },
        window: {location: {origin: 'https://app.example'}},
        URL, setTimeout: function(fn) { timers.push(fn); return timers.length; }, clearTimeout: function() {},
        fetch: async function(url) {
            return {ok: true, status: 200, json: async function() {
                return url.includes('/entries/') ? {entries} : {content: 'brief'};
            }};
        },
        L: {
            map: function() { return map; },
            tileLayer: function(url, options) {
                assert.equal(url, config.url); assert.equal(options.attribution, 'Provider');
                tileCount++; return tiles;
            },
            layerGroup: function() { return layer; },
            marker: function(coords) {
                assert.deepEqual(Array.from(coords), [10, 20]);
                return {addTo: function() { return this; }, bindPopup: function(html) { markers.push(html); }};
            },
            featureGroup: function() { return {getBounds: function() { return {pad: function() { return {}; }}; }}; }
        }
    };
    context.document.getElementById('cp-feed-map-status');
    Object.defineProperty(elements['cp-feed-map-status'], 'textContent', {set: function() { notices++; }});
    vm.runInNewContext(input.javascript, context);
    await new Promise(setImmediate);
    assert.equal(markers.length, entries.length);
    assert.equal(fits, entries.length);
    assert.equal(views.length, entries.length ? 1 : 2);
    if (entries.length) assert.ok(markers[0].includes('&lt;test>'));
    assert.equal(tileCount, enabled ? 1 : 0);
    if (enabled) {
        for (let i = 0; i < 10; i++) tileErrors();
        assert.equal(timers.length, 1);
        timers.shift()();
        assert.equal(removals, 1);
        assert.equal(markers.length, entries.length);
    }
    assert.equal(notices, 1);
    assert.equal(elements['cp-feed-map-status'].hidden, false);
}
}
})().catch(function(error) { console.error(error); process.exit(1); });
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", harness],
            input=json.dumps({"javascript": javascript}),
            text=True, capture_output=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
