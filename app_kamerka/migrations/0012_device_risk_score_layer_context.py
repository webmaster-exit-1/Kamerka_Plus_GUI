from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app_kamerka", "0011_vulnintelligence_cvedb_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="device",
            name="risk_score",
            field=models.IntegerField(
                default=0,
                help_text=(
                    "Composite risk score 0–100 computed by "
                    "app_kamerka.enrichment.compute_risk_score(). "
                    "Higher = more likely high-risk device."
                ),
            ),
        ),
        migrations.AddField(
            model_name="device",
            name="layer_context",
            field=models.JSONField(
                default=dict,
                blank=True,
                help_text=(
                    "JSON context from enrichment: nearby_infra, recent_alerts, "
                    "kev_listed, likely_honeypot."
                ),
            ),
        ),
    ]
