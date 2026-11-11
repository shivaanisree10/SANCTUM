from enum import IntEnum


class ExitCode(IntEnum):
    SUCCESS = 0
    VERIFICATION_FAILURE = 1
    SAFETY_REFUSAL = 2
    DEVICE_ERROR = 3
    OPERATOR_ABORT = 4
    GENERAL_ERROR = 5
