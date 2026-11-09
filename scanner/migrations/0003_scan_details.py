from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0002_scan_areas'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='details',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='scan',
            name='skipped',
            field=models.CharField(blank=True, max_length=300),
        ),
    ]