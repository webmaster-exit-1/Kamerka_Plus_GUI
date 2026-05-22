from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app_kamerka", "0014_watchlist"),
    ]

    operations = [
        migrations.AddField(
            model_name="device",
            name="is_camera_candidate",
            field=models.BooleanField(
                db_index=True,
                default=False,
                help_text=(
                    "True when camera classification heuristics identify this asset as "
                    "a likely camera/NVR endpoint."
                ),
            ),
        ),
        migrations.AddField(
            model_name="device",
            name="camera_score",
            field=models.IntegerField(
                db_index=True,
                default=0,
                help_text=(
                    "Heuristic camera confidence score (0–100) derived from ports, "
                    "tags, product strings, and RTSP hints."
                ),
            ),
        ),
        migrations.AddField(
            model_name="device",
            name="camera_reasons",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="List of rule hits that contributed to camera_score.",
            ),
        ),
    ]
