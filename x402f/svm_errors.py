"""Structured simulation failures without RPC bodies or signed transactions."""

from solders.transaction_status import (
    InstructionErrorCustom,
    InstructionErrorFieldless,
    TransactionErrorFieldless,
    TransactionErrorInstructionError,
)


class SvmSimulationError(RuntimeError):
    def __init__(self, error: object) -> None:
        super().__init__("SVM payment transaction simulation failed")
        self.error = error

    def is_insufficient_token_balance(self, transfer_index: int) -> bool:
        # SPL Token custom error 1 is InsufficientFunds. A wallet can append
        # other programs whose custom error 1 has a completely different meaning.
        return (
            isinstance(self.error, TransactionErrorInstructionError)
            and self.error.index == transfer_index
            and self.error.err == InstructionErrorCustom(1)
        )

    def diagnostic(self) -> dict[str, str | int]:
        error = self.error
        fields: dict[str, str | int] = {"transaction_error": type(error).__name__}
        if isinstance(error, TransactionErrorFieldless):
            fields["transaction_error"] = str(error).split(".")[-1]
        elif isinstance(error, TransactionErrorInstructionError):
            fields["instruction_index"] = error.index
            fields["instruction_error"] = type(error.err).__name__
            if isinstance(error.err, InstructionErrorCustom):
                fields["custom_error"] = error.err.code
            elif isinstance(error.err, InstructionErrorFieldless):
                fields["instruction_error"] = str(error.err).split(".")[-1]
        return fields

    def is_missing_token_account(self, transfer_index: int) -> bool:
        # Preserve the existing classification for the standard transfer layout.
        # Other InvalidAccountData failures remain generic, with typed diagnostics.
        return (
            isinstance(self.error, TransactionErrorInstructionError)
            and self.error.index == transfer_index == 2
            and self.error.err == InstructionErrorFieldless.InvalidAccountData
        )
