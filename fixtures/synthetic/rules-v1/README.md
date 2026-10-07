# Synthetic `rules-v1` classifier corpus

The corpus contains five fixture classes for every positive v1 label:
positive, negative, Unicode-separated, obfuscated, and boundary-near-miss.
The protocol integration test loads these values, derives completed
`redaction-v1` episodes, and checks the immutable assessment output. The
strings are harmless classifier phrases and contain no credential-shaped
material or authorization decision.
