from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import Iterable

from tree_sitter_language_pack import get_parser

from .parsers import filename_to_lang


@dataclass(frozen=True)
class DefinitionRecord:
    symbol: str
    code: str
    start_line: int
    end_line: int
    tags: tuple[str, ...]
    definition_kind: str


@dataclass(frozen=True)
class CallableCandidate:
    container_node: object
    callable_node: object
    item_type: str


class FunctionSplitter:
    # Tree-sitter node types that introduce a class-like scope.
    CLASS_TYPES = {
        "class_definition",
        "class_declaration",
        "interface_declaration",
        "trait_declaration",
        "class_specifier",
        "struct_specifier",
        "impl_item",
        "trait_item",
        "class",
        "record_declaration",
    }

    # Tree-sitter node types that should be emitted as function-level snippets.
    FUNC_TYPES = {
        "function_definition",
        "decorated_definition",
        "function_declaration",
        "method_declaration",
        "method_definition",
        "arrow_function",
        "function_item",
        "method",
        "singleton_method",
        "constructor_declaration",
        "local_function_statement",
    }

    BODY_TYPES = {
        "block",
        "class_body",
        "statement_block",
        "compound_statement",
        "declaration_list",
        "field_declaration_list",
        "body_statement",
    }

    ROOT_SCOPE_TYPES = {"module", "program", "source_file"}
    IDENTIFIER_KINDS = {"identifier", "name", "variable_name", "property_identifier"}
    PARAMETER_SCOPE_TYPES = {"parameters", "formal_parameters", "parameter_list", "simple_parameter"}
    PYTHON_DEFINITION_TYPES = {"assignment"}
    JS_DEFINITION_TYPES = {"lexical_declaration", "variable_declaration"}
    JS_VALUE_FUNC_TYPES = {"function_expression", "arrow_function"}
    GO_DEFINITION_TYPES = {"var_declaration", "const_declaration"}
    JAVA_DEFINITION_TYPES = {"field_declaration"}
    PHP_DEFINITION_TYPES = {"expression_statement"}

    REGEX_TOKENS = {"re", "regex", "regexp", "pattern"}
    ALLOWLIST_TOKENS = {"allow", "allowed", "deny", "denied", "whitelist", "blacklist", "safe", "trusted", "valid", "validate"}
    PATH_TOKENS = {"path", "dir", "directory", "root", "base", "backup", "static", "file", "folder"}
    HELPER_TOKENS = {"sanitize", "escape", "normalize", "valid", "validate", "allow", "deny", "backup", "path"}

    REGEX_TEXT_MARKERS = (
        "re.compile(",
        "regex.compile(",
        "regexp.mustcompile(",
        "regexp.compile(",
        "pattern.compile(",
        "new regexp(",
        "preg_match(",
        "preg_replace(",
    )
    PATH_TEXT_MARKERS = (
        "path(",
        "resolve(",
        "relative_to(",
        "os.path.join(",
        "filepath.join(",
    )
    ALLOWLIST_TEXT_MARKERS = ("{", "[", "(")

    LANGUAGE_TIERS = {
        "python": "tier1",
        "javascript": "tier1",
        "typescript": "tier1",
        "java": "tier2",
        "go": "tier2",
        "php": "tier2",
    }

    MAX_ENRICHED_DEFINITIONS = 3
    MAX_DEFINITION_LINES = 15
    MAX_HELPER_LINES = 8

    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self.code = self.file_path.read_text(encoding="utf-8", errors="ignore")
        self.code_bytes = self.code.encode("utf-8")
        self.lines = self.code.splitlines()
        self.lang = filename_to_lang(self.file_path.name)
        if not self.lang:
            raise LookupError(f"Unsupported language for function splitting: {self.file_path}")
        self.parser = get_parser(self.lang)
        self.tree = self.parser.parse(self.code)
        self.language_tier = self.LANGUAGE_TIERS.get(self.lang, "tier3")
        self.scope_definition_index = self._build_scope_definition_index()

    def split(self) -> list[dict[str, object]]:
        return self._walk_and_collect(self._root_node(), class_stack=[], scope_stack=[])

    def _get_signature_header(self, node) -> str:
        body_node = next((child for child in self._children(node) if self._node_kind(child) in self.BODY_TYPES), None)
        start_line = self._start_row(node)
        if body_node:
            body_start_line = self._start_row(body_node)
            end_line = body_start_line if body_start_line == start_line else body_start_line - 1
            return "\n".join(self.lines[start_line : end_line + 1])
        return self.lines[start_line]

    def _get_node_indent(self, node) -> str:
        line_text = self.lines[self._start_row(node)]
        return line_text[: len(line_text) - len(line_text.lstrip())]

    def _walk_and_collect(self, node, class_stack: list[str], scope_stack: list[tuple]) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        current_stack = list(class_stack)
        current_scope_stack = list(scope_stack)

        if self._node_kind(node) in self.CLASS_TYPES:
            current_stack.append(self._get_signature_header(node))
            current_scope_stack.append(self._node_key(node))

        candidate = self._match_callable_candidate(node, current_stack)
        if candidate is not None:
            start_line = self._start_row(candidate.container_node)
            end_line = self._end_row(candidate.container_node)
            func_code = "\n".join(self.lines[start_line : end_line + 1])

            if current_stack and candidate.item_type == "method":
                combined_headers = "\n".join(current_stack)
                indent = self._get_node_indent(candidate.container_node)
                body_code = f"{combined_headers}\n{indent}⋮\n{func_code}"
            else:
                body_code = func_code

            enriched_code, enrichment_meta = self._enrich_function_code(
                candidate.callable_node,
                body_code,
                current_scope_stack,
            )
            results.append(
                {
                    "type": candidate.item_type,
                    "start_line": start_line + 1,
                    "end_line": end_line + 1,
                    "code": enriched_code,
                    **enrichment_meta,
                }
            )
            return results

        for child in self._children(node):
            results.extend(self._walk_and_collect(child, current_stack, current_scope_stack))

        return results

    def _enrich_function_code(self, function_node, body_code: str, scope_stack: list[tuple]) -> tuple[str, dict[str, object]]:
        base_meta = {
            "context_enrichment_applied": False,
            "enriched_context_symbols": [],
            "enriched_definition_count": 0,
            "enriched_language_tier": self.language_tier,
        }
        if self.language_tier == "tier3":
            return body_code, base_meta

        available_definitions: dict[str, DefinitionRecord] = {}
        root_key = self._node_key(self._root_node())
        for scope_key in [root_key, *scope_stack]:
            for symbol, record in self.scope_definition_index.get(scope_key, {}).items():
                available_definitions[symbol] = record

        if not available_definitions:
            return body_code, base_meta

        referenced_symbols = self._extract_referenced_symbols(function_node)
        matching_records: list[DefinitionRecord] = []
        for symbol in referenced_symbols:
            record = available_definitions.get(symbol)
            if record is not None:
                matching_records.append(record)

        if not matching_records:
            return body_code, base_meta

        deduped_records = list({record.symbol: record for record in matching_records}.values())
        deduped_records.sort(key=self._definition_priority)
        selected_records = deduped_records[: self.MAX_ENRICHED_DEFINITIONS]
        if not selected_records:
            return body_code, base_meta

        prefix = "\n\n".join(record.code for record in selected_records)
        enriched_code = f"{prefix}\n\n{body_code}"
        return enriched_code, {
            "context_enrichment_applied": True,
            "enriched_context_symbols": [record.symbol for record in selected_records],
            "enriched_definition_count": len(selected_records),
            "enriched_language_tier": self.language_tier,
        }

    def _build_scope_definition_index(self) -> dict[tuple, dict[str, DefinitionRecord]]:
        root = self._root_node()
        index: dict[tuple, dict[str, DefinitionRecord]] = {
            self._node_key(root): self._collect_scope_definitions(root),
        }
        for node in self._iter_nodes(root):
            if self._node_kind(node) in self.CLASS_TYPES:
                index[self._node_key(node)] = self._collect_scope_definitions(node)
        return index

    def _collect_scope_definitions(self, scope_node) -> dict[str, DefinitionRecord]:
        definitions: dict[str, DefinitionRecord] = {}
        for child in self._scope_children(scope_node):
            for record in self._extract_definition_records(child):
                definitions[record.symbol] = record
        return definitions

    def _scope_children(self, scope_node) -> list:
        scope_kind = self._node_kind(scope_node)
        if scope_kind in self.ROOT_SCOPE_TYPES:
            return self._children(scope_node)
        body_node = next((child for child in self._children(scope_node) if self._node_kind(child) in self.BODY_TYPES), None)
        return self._children(body_node) if body_node else []

    def _extract_definition_records(self, node) -> list[DefinitionRecord]:
        kind = self._node_kind(node)
        if kind in self.FUNC_TYPES or (self.lang in {"javascript", "typescript"} and kind in {"pair", "assignment_expression"}):
            helper_record = self._extract_helper_definition(node)
            return [helper_record] if helper_record else []

        if self.lang == "python" and kind in self.PYTHON_DEFINITION_TYPES:
            record = self._extract_assignment_definition(node)
            return [record] if record else []

        if self.lang in {"javascript", "typescript"} and kind in self.JS_DEFINITION_TYPES:
            return self._extract_variable_declarator_records(node)

        if self.lang == "go" and kind in self.GO_DEFINITION_TYPES:
            return self._extract_var_spec_records(node)

        if self.lang == "java" and kind in self.JAVA_DEFINITION_TYPES:
            return self._extract_field_definition_records(node)

        if self.lang == "php" and kind in self.PHP_DEFINITION_TYPES:
            child = next((child for child in self._children(node) if self._node_kind(child) == "assignment_expression"), None)
            record = self._extract_assignment_definition(child) if child else None
            return [record] if record else []

        return []

    def _extract_assignment_definition(self, node) -> DefinitionRecord | None:
        if node is None:
            return None
        left = node.child_by_field_name("left") or (self._children(node)[0] if self._children(node) else None)
        right = node.child_by_field_name("right") or (self._children(node)[-1] if self._children(node) else None)
        symbol = self._extract_symbol_name(left)
        if not symbol or right is None:
            return None
        return self._make_definition_record(symbol, node, self._definition_tags(symbol, self._node_text(right)))

    def _extract_variable_declarator_records(self, declaration_node) -> list[DefinitionRecord]:
        records: list[DefinitionRecord] = []
        for child in self._children(declaration_node):
            if self._node_kind(child) != "variable_declarator":
                continue
            name_node = child.child_by_field_name("name")
            value_node = child.child_by_field_name("value")
            symbol = self._extract_symbol_name(name_node)
            if not symbol or value_node is None:
                continue
            record = self._make_definition_record(symbol, declaration_node, self._definition_tags(symbol, self._node_text(value_node)))
            if record:
                records.append(record)
        return records

    def _extract_var_spec_records(self, declaration_node) -> list[DefinitionRecord]:
        records: list[DefinitionRecord] = []
        for child in self._children(declaration_node):
            if self._node_kind(child) not in {"var_spec", "const_spec"}:
                continue
            name_node = child.child_by_field_name("name")
            value_node = child.child_by_field_name("value")
            symbol = self._extract_symbol_name(name_node)
            if not symbol or value_node is None:
                continue
            record = self._make_definition_record(symbol, declaration_node, self._definition_tags(symbol, self._node_text(value_node)))
            if record:
                records.append(record)
        return records

    def _extract_field_definition_records(self, field_node) -> list[DefinitionRecord]:
        records: list[DefinitionRecord] = []
        for child in self._children(field_node):
            if self._node_kind(child) != "variable_declarator":
                continue
            name_node = child.child_by_field_name("name")
            value_node = child.child_by_field_name("value")
            symbol = self._extract_symbol_name(name_node)
            if not symbol or value_node is None:
                continue
            record = self._make_definition_record(symbol, field_node, self._definition_tags(symbol, self._node_text(value_node)))
            if record:
                records.append(record)
        return records

    def _extract_helper_definition(self, function_node) -> DefinitionRecord | None:
        symbol = self._extract_callable_symbol(function_node)
        if not symbol:
            return None
        tags = self._helper_tags(symbol)
        if not tags:
            return None
        start_line = self._start_row(function_node)
        end_line = self._end_row(function_node)
        if end_line - start_line + 1 > self.MAX_HELPER_LINES:
            return None
        return self._make_definition_record(symbol, function_node, tags, definition_kind="helper")

    def _make_definition_record(
        self,
        symbol: str,
        node,
        tags: set[str],
        definition_kind: str = "definition",
    ) -> DefinitionRecord | None:
        if not tags:
            return None
        start_line = self._start_row(node)
        end_line = self._end_row(node)
        if end_line - start_line + 1 > self.MAX_DEFINITION_LINES:
            return None
        code = self._node_text(node).strip()
        if not code:
            return None
        return DefinitionRecord(
            symbol=symbol,
            code=code,
            start_line=start_line + 1,
            end_line=end_line + 1,
            tags=tuple(sorted(tags)),
            definition_kind=definition_kind,
        )

    def _definition_tags(self, symbol: str, definition_text: str) -> set[str]:
        tokens = set(self._symbol_tokens(symbol))
        lowered_text = definition_text.lower()
        tags: set[str] = set()

        if tokens & self.REGEX_TOKENS or any(marker in lowered_text for marker in self.REGEX_TEXT_MARKERS):
            tags.add("regex")
        if tokens & self.ALLOWLIST_TOKENS:
            tags.add("allowlist")
        if tokens & self.PATH_TOKENS and any(marker in lowered_text for marker in self.PATH_TEXT_MARKERS):
            tags.add("path")
        if tokens & self.PATH_TOKENS and not tags:
            tags.add("path")
        if tokens & self.ALLOWLIST_TOKENS and any(marker in definition_text for marker in self.ALLOWLIST_TEXT_MARKERS):
            tags.add("allowlist")
        return tags

    def _helper_tags(self, symbol: str) -> set[str]:
        tokens = set(self._symbol_tokens(symbol))
        if tokens & self.HELPER_TOKENS:
            return {"helper"}
        return set()

    def _extract_referenced_symbols(self, function_node) -> set[str]:
        function_root = self._callable_root_node(function_node)
        referenced: set[str] = set()
        excluded = self._extract_parameter_symbols(function_root)
        function_name = self._extract_callable_symbol(function_node)
        if function_name:
            excluded.add(function_name)

        def walk(node) -> None:
            for child in self._children(node):
                child_kind = self._node_kind(child)
                if child_kind in self.FUNC_TYPES | self.CLASS_TYPES | self.JS_VALUE_FUNC_TYPES:
                    continue
                if child_kind in self.IDENTIFIER_KINDS:
                    symbol = self._extract_symbol_name(child)
                    if symbol and symbol not in excluded:
                        referenced.add(symbol)
                walk(child)

        walk(function_root)
        return referenced

    def _extract_parameter_symbols(self, function_node) -> set[str]:
        function_root = self._callable_root_node(function_node)
        params: set[str] = set()
        for child in self._children(function_root):
            if self._node_kind(child) not in self.PARAMETER_SCOPE_TYPES:
                continue
            for param_node in self._iter_nodes(child):
                symbol = self._extract_symbol_name(param_node)
                if symbol:
                    params.add(symbol)
        return params

    def _definition_priority(self, record: DefinitionRecord) -> tuple[int, int]:
        score = 0
        if "regex" in record.tags:
            score += 100
        if "allowlist" in record.tags:
            score += 80
        if "path" in record.tags:
            score += 60
        if "helper" in record.tags:
            score += 40
        return (-score, record.start_line)

    def _extract_symbol_name(self, node) -> str | None:
        if node is None:
            return None
        kind = self._node_kind(node)
        if kind == "pair":
            return self._extract_symbol_name(node.child_by_field_name("key"))
        if kind == "assignment_expression":
            left = node.child_by_field_name("left") or (self._children(node)[0] if self._children(node) else None)
            return self._extract_assignment_member_symbol(left)
        if kind == "variable_name":
            for child in self._children(node):
                symbol = self._extract_symbol_name(child)
                if symbol:
                    return symbol
            text = self._node_text(node).strip()
            return text[1:] if text.startswith("$") else text or None
        if kind in {"identifier", "name", "property_identifier", "type_identifier"}:
            text = self._node_text(node).strip()
            return text[1:] if text.startswith("$") else text or None
        if node.child_by_field_name("name") is not None:
            return self._extract_symbol_name(node.child_by_field_name("name"))
        return None

    def _match_callable_candidate(self, node, class_stack: list[str]) -> CallableCandidate | None:
        return self._match_default_callable_candidate(node, class_stack) or self._match_javascript_callable_candidate(node)

    def _match_default_callable_candidate(self, node, class_stack: list[str]) -> CallableCandidate | None:
        node_kind = self._node_kind(node)
        if node_kind not in self.FUNC_TYPES:
            return None

        start_line = self._start_row(node)
        is_go_method = node_kind == "method_declaration" and any(
            self._node_kind(child) == "receiver" for child in self._children(node)
        )
        is_cpp_scoped = "::" in self.lines[start_line] and node_kind == "function_definition"
        if class_stack and not (is_go_method or is_cpp_scoped):
            item_type = "method"
        else:
            item_type = "method" if "method" in node_kind or "constructor" in node_kind else "function"
        return CallableCandidate(container_node=node, callable_node=node, item_type=item_type)

    def _match_javascript_callable_candidate(self, node) -> CallableCandidate | None:
        if self.lang not in {"javascript", "typescript"}:
            return None
        return self._match_js_pair_callable(node) or self._match_js_assignment_callable(node)

    def _match_js_pair_callable(self, node) -> CallableCandidate | None:
        if self._node_kind(node) != "pair":
            return None
        value_node = node.child_by_field_name("value")
        if value_node is None or self._node_kind(value_node) not in self.JS_VALUE_FUNC_TYPES:
            return None
        return CallableCandidate(container_node=node, callable_node=value_node, item_type="method")

    def _match_js_assignment_callable(self, node) -> CallableCandidate | None:
        if self._node_kind(node) != "assignment_expression":
            return None
        right = node.child_by_field_name("right")
        if right is None or self._node_kind(right) not in self.JS_VALUE_FUNC_TYPES:
            return None
        return CallableCandidate(container_node=node, callable_node=right, item_type="function")

    def _callable_root_node(self, node):
        candidate = self._match_javascript_callable_candidate(node)
        return candidate.callable_node if candidate is not None else node

    def _extract_callable_symbol(self, node) -> str | None:
        return self._extract_symbol_name(node)

    def _extract_assignment_member_symbol(self, node) -> str | None:
        if node is None:
            return None
        kind = self._node_kind(node)
        if kind in {"identifier", "property_identifier", "name", "type_identifier", "variable_name"}:
            return self._extract_symbol_name(node)
        property_node = node.child_by_field_name("property")
        if property_node is not None:
            symbol = self._extract_symbol_name(property_node)
            if symbol:
                return symbol
        for child in reversed(self._children(node)):
            symbol = self._extract_assignment_member_symbol(child)
            if symbol:
                return symbol
        return None

    @staticmethod
    def _symbol_tokens(symbol: str) -> list[str]:
        stripped = symbol.lstrip("$")
        tokens = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|_|$)|[A-Z]?[a-z]+|\d+", stripped)
        if not tokens:
            tokens = [part for part in re.split(r"[_\W]+", stripped) if part]
        if not tokens:
            return [stripped.lower()] if stripped else []
        return [token.lower() for token in tokens]

    def _node_text(self, node) -> str:
        start = self._start_byte(node)
        end = self._end_byte(node)
        return self.code_bytes[start:end].decode("utf-8", errors="ignore")

    def _root_node(self):
        root = self.tree.root_node
        return root() if callable(root) else root

    def _iter_nodes(self, node) -> Iterable:
        yield node
        for child in self._children(node):
            yield from self._iter_nodes(child)

    @staticmethod
    def _children(node) -> list:
        children = getattr(node, "children", None)
        if children is not None:
            return list(children)
        child_count = node.child_count()
        return [node.child(index) for index in range(child_count)]

    @staticmethod
    def _node_kind(node) -> str:
        kind = getattr(node, "type", None)
        if kind is not None:
            return kind
        return node.kind()

    @staticmethod
    def _start_row(node) -> int:
        start = getattr(node, "start_point", None)
        if start is not None:
            return start[0]
        return node.start_position().row

    @staticmethod
    def _end_row(node) -> int:
        end = getattr(node, "end_point", None)
        if end is not None:
            return end[0]
        return node.end_position().row

    @staticmethod
    def _start_byte(node) -> int:
        start = getattr(node, "start_byte", None)
        return start() if callable(start) else start

    @staticmethod
    def _end_byte(node) -> int:
        end = getattr(node, "end_byte", None)
        return end() if callable(end) else end

    def _node_key(self, node) -> tuple:
        start_position = getattr(node, "start_position", None)
        end_position = getattr(node, "end_position", None)
        if callable(start_position):
            start_point = start_position()
            end_point = end_position()
            start = (start_point.row, start_point.column)
            end = (end_point.row, end_point.column)
        else:
            start_point = getattr(node, "start_point", None)
            end_point = getattr(node, "end_point", None)
            start = start_point if start_point is not None else (0, 0)
            end = end_point if end_point is not None else (0, 0)
        return (self._node_kind(node), start, end)
