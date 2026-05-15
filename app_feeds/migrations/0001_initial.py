import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="FeedSource",
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
                ("url", models.URLField(max_length=500, unique=True)),
                ("name", models.CharField(max_length=200)),
                (
                    "category",
                    models.CharField(
                        choices=[
                            ("cyber", "Cybersecurity"),
                            ("ics", "ICS/SCADA"),
                            ("geo", "Geopolitics"),
                            ("infra", "Infrastructure"),
                            ("other", "Other"),
                        ],
                        default="other",
                        max_length=20,
                    ),
                ),
                ("active", models.BooleanField(default=True)),
                ("last_fetched", models.DateTimeField(blank=True, null=True)),
                ("error_count", models.IntegerField(default=0)),
            ],
            options={
                "ordering": ["category", "name"],
            },
        ),
        migrations.CreateModel(
            name="Brief",
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
                (
                    "region",
                    models.CharField(
                        help_text="ISO-2 country code, region name, or topic keyword",
                        max_length=200,
                    ),
                ),
                ("content", models.TextField()),
                ("generated_at", models.DateTimeField(auto_now_add=True)),
                ("method", models.CharField(default="extractive", max_length=30)),
            ],
            options={
                "ordering": ["-generated_at"],
            },
        ),
        migrations.CreateModel(
            name="FeedEntry",
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
                ("title", models.CharField(default="", max_length=500)),
                ("summary", models.TextField(default="")),
                ("url", models.URLField(blank=True, max_length=500)),
                ("published", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("geo_countries", models.CharField(blank=True, default="", max_length=500)),
                ("geo_lat", models.FloatField(blank=True, null=True)),
                ("geo_lon", models.FloatField(blank=True, null=True)),
                ("entry_id", models.CharField(blank=True, db_index=True, max_length=500)),
                ("fetched_at", models.DateTimeField(auto_now_add=True)),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="entries",
                        to="app_feeds.feedsource",
                    ),
                ),
            ],
            options={
                "ordering": ["-published"],
            },
        ),
        migrations.AddConstraint(
            model_name="feedentry",
            constraint=models.UniqueConstraint(
                condition=models.Q(entry_id__gt=""),
                fields=["source", "entry_id"],
                name="unique_source_entry_id",
            ),
        ),
    ]
