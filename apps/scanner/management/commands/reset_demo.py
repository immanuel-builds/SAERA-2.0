from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import connection

class Command(BaseCommand):
    help = "Flushes the database, ensures migrations are applied, and runs both seed_knowledge_base and seed_demo."

    def handle(self, *args, **options):
        self.stdout.write(self.style.WARNING("Starting total demonstration reset..."))

        # 1. Flush the database
        self.stdout.write("Flushing all data from the database...")
        call_command('flush', interactive=False)

        # 2. Run migrations (just in case they haven't been applied)
        self.stdout.write("Ensuring all migrations are applied...")
        call_command('migrate')

        # 3. Seed Knowledge Base
        self.stdout.write("Seeding the doctrinal Knowledge Base...")
        call_command('seed_knowledge_base')

        # 4. Seed the Demonstration Scans and Lifecycle data
        self.stdout.write("Generating operational timeline (seed_demo)...")
        call_command('seed_demo')

        self.stdout.write(self.style.SUCCESS("Demo reset complete! SAERA is freshly calibrated for presentation."))
