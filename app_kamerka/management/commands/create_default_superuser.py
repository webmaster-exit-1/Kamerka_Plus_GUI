import os
import secrets
import string

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = 'Create a default superuser if no superuser exists'

    def handle(self, *args, **options):
        User = get_user_model()
        if not User.objects.filter(is_superuser=True).exists():
            username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
            email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@example.com')
            password = os.environ.get('DJANGO_SUPERUSER_PASSWORD')
            generated = False
            if not password:
                alphabet = string.ascii_letters + string.digits + string.punctuation
                password = ''.join(secrets.choice(alphabet) for _ in range(20))
                generated = True
            User.objects.create_superuser(username=username, password=password, email=email)
            self.stdout.write(
                self.style.SUCCESS(
                    f'Superuser "{username}" created successfully.'
                )
            )
            if generated:
                self.stdout.write(
                    self.style.WARNING(
                        f'Generated password: {password}\n'
                        'Set DJANGO_SUPERUSER_PASSWORD to specify your own password.'
                    )
                )
        else:
            self.stdout.write('A superuser already exists. No action taken.')
