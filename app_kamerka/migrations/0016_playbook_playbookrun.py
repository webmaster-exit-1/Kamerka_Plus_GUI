from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("app_kamerka", "0015_device_camera_candidate_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="Playbook",
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
                ("name", models.CharField(max_length=120, unique=True)),
                ("description", models.TextField(blank=True, default="")),
                (
                    "steps",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text=(
                            "Ordered list of step dicts: "
                            '[{"tool": "screenshot", "order": 1, "exec_type": "chain"}]'
                        ),
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="PlaybookRun",
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
                    "playbook",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="runs",
                        to="app_kamerka.playbook",
                    ),
                ),
                (
                    "device_ids",
                    models.JSONField(
                        blank=True,
                        default=list,
                        help_text="Primary keys of the Device records targeted by this run.",
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("running", "Running"),
                            ("success", "Success"),
                            ("failure", "Failure"),
                        ],
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("task_runs", models.JSONField(blank=True, default=list)),
                ("error", models.TextField(blank=True, default="")),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
            ],
            options={
                "ordering": ["-started_at"],
            },
        ),
    ]
