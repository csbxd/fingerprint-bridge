"""The report's expected coverage; unknown/missing cells cannot become passes."""
ARCHITECTURES = ("amd64", "arm64")
DISTRIBUTIONS = ("ubuntu-24.04", "debian-13", "fedora-43", "alpine-3.23")
CLIENT_PROTOCOLS = {
    "python": ("http/1.1",),
    "node": ("http/1.1", "h2"),
    "go": ("http/1.1", "h2"),
    "java": ("http/1.1", "h2"),
    "rust": ("http/1.1", "h2"),
}
CASES = tuple((client, protocol) for client, protocols in CLIENT_PROTOCOLS.items() for protocol in protocols)
SAMPLES = ("direct-1", "direct-2", "bridged")
LAYERS = ("tls", "http", "tcp")
