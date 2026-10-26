"""Custom exception hierarchy for pysskey."""


class PysskeyError(Exception):
    """Base exception for all pysskey errors."""


class OriginMismatchError(PysskeyError):
    """Raised when the origin does not match the rp_id."""


class CredentialExcludedError(PysskeyError):
    """Raised when a credential in excludeCredentials already exists in the store."""


class NoCredentialsFoundError(PysskeyError):
    """Raised when no matching credentials are found during authentication."""


class UnsupportedAlgorithmError(PysskeyError):
    """Raised when no supported algorithm is found in pubKeyCredParams."""


class UserVerificationError(PysskeyError):
    """Raised when user presence or user verification is denied."""
