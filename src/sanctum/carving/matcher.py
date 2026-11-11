from collections import deque
from typing import Dict, List, Tuple, Any


class TrieNode:
    def __init__(self):
        self.transitions: Dict[int, TrieNode] = {}
        self.fail: TrieNode = None
        self.outputs: List[Any] = []


class AhoCorasickMatcher:
    """
    Aho-Corasick streaming multi-pattern matcher.
    Searches for all file signature headers simultaneously in linear O(N) time.
    """

    def __init__(self):
        self.root = TrieNode()
        self._is_compiled = False

    def add_pattern(self, pattern: bytes, payload: Any) -> None:
        """Adds a pattern byte-sequence associated with a FileSignature payload."""
        if not pattern:
            return
        node = self.root
        for b in pattern:
            if b not in node.transitions:
                node.transitions[b] = TrieNode()
            node = node.transitions[b]
        node.outputs.append((len(pattern), payload))
        self._is_compiled = False

    def compile(self) -> None:
        """Constructs failure links using BFS."""
        queue = deque()

        # Set fail link for depth 1 nodes to root
        for b, child in self.root.transitions.items():
            child.fail = self.root
            queue.append(child)

        while queue:
            curr = queue.popleft()

            for b, child in curr.transitions.items():
                queue.append(child)
                fail_node = curr.fail

                while fail_node and b not in fail_node.transitions:
                    fail_node = fail_node.fail

                child.fail = fail_node.transitions[b] if fail_node else self.root
                child.outputs.extend(child.fail.outputs)

        self._is_compiled = True

    def search(self, data: bytes) -> List[Tuple[int, Any]]:
        """
        Scans data buffer and returns a list of (start_offset, payload).
        """
        if not self._is_compiled:
            self.compile()

        matches: List[Tuple[int, Any]] = []
        node = self.root

        for idx, b in enumerate(data):
            while node and b not in node.transitions:
                node = node.fail

            if not node:
                node = self.root
                continue

            node = node.transitions[b]
            for pat_len, payload in node.outputs:
                match_start = idx - pat_len + 1
                matches.append((match_start, payload))

        return matches
