from django.core.management.base import BaseCommand

from scanner.engine import run_scan


class Command(BaseCommand):
    help = 'Run a security scan now (same as the Run scan button).'

    def handle(self, *args, **opts):
        scan = run_scan()
        self.stdout.write(self.style.SUCCESS(
            f'Scan done: {scan.new_count} new, {scan.fixed_count} fixed, '
            f'{scan.open_count} open.'))
        if scan.errors:
            self.stdout.write(self.style.WARNING('Checks that could not run: ' + scan.errors))
