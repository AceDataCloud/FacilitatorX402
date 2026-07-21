from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from x402f.models import X402Authorization
from x402f.official import configured_base_network


class Command(BaseCommand):
    help = "Fail while nonterminal legacy x402 authorizations remain"

    def add_arguments(self, parser):  # noqa: ANN001
        parser.add_argument(
            "--fail-expired",
            action="store_true",
            help="Mark expired, unprepared legacy verified authorizations as failed",
        )

    def handle(self, *args, **options):  # noqa: ARG002
        base_network = configured_base_network()
        if options["fail_expired"]:
            failed = (
                X402Authorization.objects.filter(
                    status=X402Authorization.Status.VERIFIED,
                    valid_before__lt=timezone.now(),
                    transaction_hash__isnull=True,
                    prepared_transaction__isnull=True,
                )
                .exclude(payment_requirements__network=base_network)
                .update(status=X402Authorization.Status.FAILED)
            )
            self.stdout.write(f"Marked {failed} expired legacy authorizations as failed")

        nonterminal = X402Authorization.objects.filter(
            status__in=[X402Authorization.Status.VERIFIED, X402Authorization.Status.SETTLING]
        ).exclude(payment_requirements__network=base_network)
        count = nonterminal.count()
        if count:
            raise CommandError(f"{count} nonterminal legacy x402 authorizations must be drained before cutover")
        self.stdout.write(self.style.SUCCESS("Official x402 v2 cutover preflight passed"))
