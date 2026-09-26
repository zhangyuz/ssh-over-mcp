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
