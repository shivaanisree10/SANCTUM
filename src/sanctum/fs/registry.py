import logging
from typing import List, Type, Tuple, Optional
from sanctum.dal import BaseDevice
from sanctum.fs.base import BaseFileSystemParser

logger = logging.getLogger("sanctum.fs.registry")


class FileSystemRegistry:
    """
    Plugin registry for forensic filesystem parsers.
    Probes candidate plugins, sorts by confidence score, and activates the best match.
    """

    def __init__(self):
        self._plugins: List[Type[BaseFileSystemParser]] = []

    def register(self, parser_cls: Type[BaseFileSystemParser]) -> None:
        """Registers a filesystem parser plugin."""
        if parser_cls not in self._plugins:
            self._plugins.append(parser_cls)
            logger.debug(f"Registered filesystem parser: {parser_cls.__name__}")

    def probe_all(self, device: BaseDevice) -> List[Tuple[Type[BaseFileSystemParser], float]]:
        """
        Runs probe() against all registered parsers and returns
        (parser_cls, confidence_score) sorted by descending confidence.
        """
        results = []
        for plugin in self._plugins:
            try:
                score = plugin.probe(device)
                score = max(0.0, min(1.0, float(score)))
                results.append((plugin, score))
            except Exception as e:
                logger.warning(f"Probe exception in parser {plugin.__name__}: {e}")
                results.append((plugin, 0.0))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def detect_and_mount(
        self, device: BaseDevice, min_confidence: float = 0.5
    ) -> Tuple[Optional[BaseFileSystemParser], float]:
        """
        Detects the filesystem using confidence scores and instantiates the winning parser.
        """
        ranked = self.probe_all(device)
        if not ranked:
            return None, 0.0

        best_cls, best_score = ranked[0]
        if best_score >= min_confidence:
            logger.info(
                f"Selected parser {best_cls.__name__} with confidence {best_score:.2f}."
            )
            return best_cls(device), best_score

        logger.info(
            f"No filesystem parser met confidence threshold {min_confidence:.2f} (best: {best_score:.2f})."
        )
        return None, best_score
