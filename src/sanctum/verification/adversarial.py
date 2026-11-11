import abc

class AdversarialInterface(abc.ABC):
    """
    Interface for the Recovery Engine to inject adversarial testing metrics
    and report any recovery artefacts found during post-erasure deep scanning.
    """
    @abc.abstractmethod
    def scan_for_artefacts(self, device) -> list[str]:
        """Returns a list of artefact descriptions if any residual data structures are found."""
        pass

class MockAdversarialScanner(AdversarialInterface):
    def scan_for_artefacts(self, device) -> list[str]:
        # For the M7 MVP demo, we assume no advanced artefacts are found 
        # unless specifically injected by a test.
        return []
