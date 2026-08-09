from django.core.management.base import BaseCommand, CommandError

from x402f.bazaar import BazaarCatalogError, refresh_catalog


class Command(BaseCommand):
    help = "Refresh the signed X402 Bazaar discovery snapshot"

    def handle(self, *args, **options):  # noqa: ANN002, ANN003
        try:
            snapshot = refresh_catalog()
        except BazaarCatalogError as exc:
            raise CommandError(str(exc)) from exc
        message = f"Activated Bazaar snapshot {snapshot.snapshot} with {snapshot.resource_count} resources"
        self.stdout.write(self.style.SUCCESS(message))
