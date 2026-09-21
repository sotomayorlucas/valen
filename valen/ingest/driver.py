"""tree-sitter driver: language loading and a thin parse helper."""

from __future__ import annotations

from typing import Dict

from tree_sitter import Language, Parser


def _load_languages() -> Dict[str, Language]:
    langs: Dict[str, Language] = {}
    try:
        import tree_sitter_python

        langs["python"] = Language(tree_sitter_python.language())
    except ImportError:  # pragma: no cover
        pass
    try:
        import tree_sitter_javascript

        langs["javascript"] = Language(tree_sitter_javascript.language())
    except ImportError:  # pragma: no cover
        pass
    try:
        import tree_sitter_java

        langs["java"] = Language(tree_sitter_java.language())
    except ImportError:  # pragma: no cover
        pass
    return langs


LANGUAGES = _load_languages()


def parser_for(language: str) -> Parser:
    """Return a tree-sitter ``Parser`` for ``language``.

    Raises ``ValueError`` if the language grammar is not installed.
    """
    if language not in LANGUAGES:
        raise ValueError(
            f"unsupported language {language!r}; available: {sorted(LANGUAGES)}"
        )
    return Parser(LANGUAGES[language])
