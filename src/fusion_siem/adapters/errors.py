class DestinationNotConfigured(Exception):
    """Selected SIEM is missing required URL, host, or token."""


class DestinationSendError(Exception):
    """Selected SIEM rejected the event or was unreachable."""
