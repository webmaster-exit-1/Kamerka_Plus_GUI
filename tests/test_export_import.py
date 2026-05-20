import csv
import io
import json
import xml.etree.ElementTree as ET

from django.test import TestCase

from app_kamerka.models import Device, Search


class ExportImportRoundTripTests(TestCase):
    def setUp(self):
        self.search = Search.objects.create(
            coordinates="0,0",
            country="US",
            ics="[]",
            coordinates_search="[]",
        )
        self.device = Device.objects.create(
            search=self.search,
            ip="1.2.3.4",
            product="CameraX",
            port="80",
            type="CAM",
            city="Austin",
            lat=30.2672,
            lon=-97.7431,
            country_code="US",
            org="ExampleOrg",
        )

    def test_csv_export_round_trip(self):
        response = self.client.get(f"/export/csv/{self.search.id}")
        self.assertEqual(response.status_code, 200)
        rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8"))))
        self.assertTrue(rows)
        row = next((r for r in rows if r.get("ip_str") == self.device.ip), None)
        self.assertIsNotNone(row)
        self.assertEqual(str(row.get("port", "")), self.device.port)
        self.assertEqual(row.get("country_code"), self.device.country_code)

    def test_kml_export_round_trip(self):
        response = self.client.get(f"/export/kml/{self.search.id}")
        self.assertEqual(response.status_code, 200)
        root = ET.fromstring(response.content)
        ns = {"k": "http://www.opengis.net/kml/2.2"}
        placemarks = root.findall(".//k:Placemark", ns)
        self.assertTrue(placemarks)
        names = [p.findtext("k:name", default="", namespaces=ns) for p in placemarks]
        self.assertIn(self.device.ip, names)

    def test_geojson_export_round_trip(self):
        response = self.client.get(f"/api/export/geojson/{self.search.id}")
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content.decode("utf-8"))
        self.assertEqual(payload.get("type"), "FeatureCollection")
        features = payload.get("features", [])
        self.assertTrue(features)
        feature = next(
            (
                item
                for item in features
                if item.get("properties", {}).get("ip") == self.device.ip
            ),
            None,
        )
        self.assertIsNotNone(feature)
        props = feature["properties"]
        self.assertEqual(props.get("country"), self.device.country_code)
        self.assertEqual(props.get("product"), self.device.product)
