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
    try:
        import tree_sitter_solidity

        langs["solidity"] = Language(tree_sitter_solidity.language())
    except ImportError:  # pragma: no cover
        pass
    for name, mod in (
        ("c", "tree_sitter_c"),
        ("cpp", "tree_sitter_cpp"),
        ("rust", "tree_sitter_rust"),
        ("csharp", "tree_sitter_c_sharp"),
        ("go", "tree_sitter_go"),
        ("php", "tree_sitter_php"),
        ("ruby", "tree_sitter_ruby"),
    ):
        try:
            m = __import__(mod, fromlist=["language"])
            lang_fn = getattr(m, "language", None) or getattr(m, f"language_{name}", None)
            langs[name] = Language(lang_fn())
        except Exception:  # pragma: no cover - grammar missing or API differs
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
