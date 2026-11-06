from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='scan',
            name='areas',
            field=models.CharField(blank=True, max_length=300),
        ),
    ]