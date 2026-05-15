import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="DataLayer",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("slug", models.SlugField(max_length=80, unique=True)),
                ("name", models.CharField(max_length=200)),
                ("layer_type", models.CharField(default="point", max_length=30)),
                ("source_url", models.URLField(blank=True, max_length=500)),
                ("refresh_minutes", models.IntegerField(default=60)),
                ("color", models.CharField(default="#00e1ff", max_length=30)),
                ("icon", models.CharField(default="●", max_length=10)),
                ("enabled", models.BooleanField(default=True)),
                ("renderer_config", models.JSONField(blank=True, default=dict)),
                ("last_refreshed", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        migrations.CreateModel(
            name="LayerFeature",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("lat", models.FloatField(blank=True, db_index=True, null=True)),
                ("lon", models.FloatField(blank=True, db_index=True, null=True)),
                ("geometry", models.JSONField(default=dict)),
                ("properties", models.JSONField(default=dict)),
                (
                    "external_id",
                    models.CharField(blank=True, db_index=True, max_length=200),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "layer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="features",
                        to="app_layers.datalayer",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="layerfeature",
            constraint=models.UniqueConstraint(
                condition=models.Q(external_id__gt=""),
                fields=["layer", "external_id"],
                name="unique_layer_external_id",
            ),
        ),
    ]
