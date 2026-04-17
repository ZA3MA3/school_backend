from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0009_skill_skill_importance'),
    ]

    operations = [
        migrations.AddField(
            model_name='student',
            name='gender',
            field=models.BooleanField(default=True, help_text='True for male, False for female'),
        ),
        migrations.AddField(
            model_name='student',
            name='scholarship_holder',
            field=models.BooleanField(default=False, help_text='True if has scholarship'),
        ),
    ]