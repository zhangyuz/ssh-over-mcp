# Ephemeral PR-native shadow live canary

This temporary, non-production PR exists solely to generate an ordinary
same-repository non-draft pull_request CI completion after the
trusted-main, hosted-only PR-native shadow listener became active.

Acceptance is external to this document: the trusted-main workflow_run
observer should report only METADATA_MATCH_SHADOW with all three
authorization flags false, and must schedule zero additional native Mac
jobs or repository commit statuses. Closing the canary is expected; it
must not be merged or treated as new product scope.
