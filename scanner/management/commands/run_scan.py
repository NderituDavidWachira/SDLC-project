from django.core.management.base import BaseCommand, CommandError

from scanner.checks import AREAS, DEFAULT_AREAS
from scanner.engine import clean_areas, run_scan


class Command(BaseCommand):
    help = 'Run a security scan now (same as the Run scan button).'

    def add_arguments(self, parser):
        parser.add_argument('--areas', help='Comma-separated areas, for example vscode,git')
        parser.add_argument('--list', action='store_true', help='List the available areas')

    def handle(self, *args, **opts):
        if opts['list']:
            for a in AREAS:
                mark = '*' if a.slug in DEFAULT_AREAS else ' '
                self.stdout.write(f'{mark} {a.slug:13} {a.label}: {a.description}')
            self.stdout.write('(* = scanned by default)')
            return
        areas = None
        if opts['areas']:
            areas = clean_areas([a.strip() for a in opts['areas'].split(',')])
            if not areas:
                raise CommandError('No valid areas given. Use --list to see them.')
        scan = run_scan(areas=areas)
        self.stdout.write(self.style.SUCCESS(
            f'Scan done ({scan.areas}): {scan.new_count} new, {scan.fixed_count} fixed, '
            f'{scan.open_count} open.'))
        if scan.errors:
            self.stdout.write(self.style.WARNING('Checks that could not run: ' + scan.errors))