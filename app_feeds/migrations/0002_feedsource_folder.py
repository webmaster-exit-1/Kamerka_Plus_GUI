from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app_feeds", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="feedsource",
            name="folder",
            field=models.CharField(
                blank=True,
                default="",
                help_text="OPML folder/group label from the reader export",
                max_length=120,
            ),
        ),
    ]