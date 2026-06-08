from __future__ import annotations

import os

PARSERS = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".go": "go",
    ".bash": "bash",
    ".c": "c",
    ".cc": "cpp",
    ".cs": "c_sharp",
    ".cl": "commonlisp",
    ".cpp": "cpp",
    ".css": "css",
    ".dockerfile": "dockerfile",
    ".dot": "dot",
    ".el": "elisp",
    ".ex": "elixir",
    ".elm": "elm",
    ".et": "embedded_template",
    ".erl": "erlang",
    ".gomod": "gomod",
    ".hack": "hack",
    ".hs": "haskell",
    ".hcl": "hcl",
    ".html": "html",
    ".java": "java",
    ".jsdoc": "jsdoc",
    ".json": "json",
    ".jl": "julia",
    ".kt": "kotlin",
    ".lua": "lua",
    ".mk": "make",
    ".md": "markdown",
    ".m": "objc",
    ".ml": "ocaml",
    ".mli": "ocaml_interface",
    ".pl": "perl",
    ".php": "php",
    ".ql": "ql",
    ".r": "r",
    ".R": "r",
    ".regex": "regex",
    ".rst": "rst",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sql": "sql",
    ".sqlite": "sqlite",
    ".tf": "hcl",
    ".toml": "toml",
    ".tsq": "tsq",
    ".tsx": "typescript",
    ".ts": "typescript",
    ".yaml": "yaml",
}


def filename_to_lang(filename: str) -> str | None:
    basename = os.path.basename(filename)
    if basename in PARSERS:
        return PARSERS[basename]

    return PARSERS.get(os.path.splitext(filename)[1])
