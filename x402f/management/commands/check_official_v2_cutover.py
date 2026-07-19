from django.core.management.base import BaseCommand, CommandError

from x402f.models import X402Authorization
from x402f.official import BASE_MAINNET


class Command(BaseCommand):
    help = "Fail while nonterminal legacy x402 authorizations remain"

    def handle(self, *args, **options):  # noqa: ARG002
        nonterminal = X402Authorization.objects.filter(
            status__in=[X402Authorization.Status.VERIFIED, X402Authorization.Status.SETTLING]
        ).exclude(payment_requirements__network=BASE_MAINNET)
        count = nonterminal.count()
        if count:
            raise CommandError(f"{count} nonterminal legacy x402 authorizations must be drained before cutover")
        self.stdout.write(self.style.SUCCESS("Official x402 v2 cutover preflight passed"))
