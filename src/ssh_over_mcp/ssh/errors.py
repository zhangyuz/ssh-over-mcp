class SSHCoreError(RuntimeError):
    """Base error for the SSH execution core."""


class SSHCredentialError(SSHCoreError):
    """Credential material could not be resolved safely."""


class SSHHostKeyVerificationError(SSHCoreError):
    """The remote server host key was malformed or not trusted."""


class SSHConnectionError(SSHCoreError):
    """The SSH connection could not be established or reused."""


class SSHPolicyDenied(SSHCoreError):
    def __init__(self, decision):
        super().__init__(decision.reason)
        self.decision = decision


class SSHApprovalRequired(SSHCoreError):
    def __init__(self, decision):
        super().__init__(decision.reason)
        self.decision = decision


class SSHRemoteResponseError(SSHCoreError):
    """The remote structured response violated its expected contract."""


class SSHRequestTimeout(SSHCoreError):
    """The remote structured request exceeded its control-plane deadline."""


class SSHOutputLimitExceeded(SSHCoreError):
    """The remote structured response exceeded its control-plane byte budget."""


class SSHRemotePolicyDenied(SSHCoreError):
    """The remote host-agent independently denied the structured request."""


class SSHRemoteOperationError(SSHCoreError):
    """The remote structured operation failed without safe public detail."""


class SSHRequestOutcomeUncertain(SSHCoreError):
    """The structured request may have reached the remote host."""
