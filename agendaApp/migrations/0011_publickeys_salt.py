# Generated by Django 4.1.4 on 2023-01-08 07:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agendaApp', '0010_requestsnewdev_salt_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='publickeys',
            name='salt',
            field=models.CharField(default='suuuuu', max_length=500),
            preserve_default=False,
        ),
    ]
