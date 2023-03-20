class ACMEToolsError(Exception):
    """Base exception for all errors raised within the `acme-tools` package."""

    pass


class InvalidOptionsError(ACMEToolsError):
    """Base exception for all errors related to invalid parameters or options."""

    pass


class InvalidDomainName(InvalidOptionsError):
    """Error raised when attempting to use an invalid domain name."""

    pass


class InvalidRecordType(InvalidOptionsError):
    """Error raised when attempting to query, create, or delete an invalid DNS record type."""

    pass


class DNSProviderError(Exception):
    """Base exception for all errors reraised by DNS providers.

    Requests failing due to DNS provider errors might be retried dependending
    on the error type.
    """

    pass


class ResourceNotFoundError(DNSProviderError):
    """Error raised by DNS providers when 404 errors are returned by provider API.

    Requests failing due to 404 errors should NOT be retried.
    """

    pass


class UnauthorizedError(DNSProviderError):
    """Error raised by DNS providers when 401 or 403 errors are returned by provider API.

    Requests failing due to unauthorized error should NOT be retried.
    """

    pass


class RateLimitExceededError(DNSProviderError):
    """Error raised by DNS providers when 429 errors are returned by provider API.

    Requests failing due to rate limit exceeded error should NOT be retried UNTIL
    oldest request expires on provider side.
    """

    pass


class ServerError(DNSProviderError):
    """Error raised by DNS providers when 500 errors are returned by provider API.

    Requests failing due to server errors should be retried.
    """

    pass


class InvalidRequestError(DNSProviderError):
    """Error raised by DNS providers when 400, 422 or 428 errors are returned by provider API.

    Requests failing due to invalid request error should NOT be retried.
    """

    pass


class RecordAlreadyExistsError(DNSProviderError):
    """Error raised by DNS providers when attempting to create an already existing DNS record
    with different value.

    Requests failing due to record already exists error should NOT be retried.
    """

    pass
