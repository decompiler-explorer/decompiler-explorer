from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.utils.crypto import get_random_string


class Command(BaseCommand):
    help = "Creates a default admin user, only if one doesn't already exist"

    def handle(self, *args, **options):
        User = get_user_model()
        if User.objects.filter(is_staff=True, is_superuser=True).exists():
            return
        password = get_random_string(24)
        User.objects.create_superuser(username='admin', email='admin@localhost', password=password)
        self.stdout.write(self.style.SUCCESS("Successfully created admin user"))
        self.stdout.write(self.style.WARNING("Please log in and change the admin's email and password"))
        self.stdout.write("Username: admin")
        self.stdout.write("Email: admin@localhost")
        self.stdout.write(f"Password: {password}")
