import re
from typing import Any, List, Set, Union


class OperatorRegistry:
    """Catálogo cerrado de operadores de comparación para evaluación declarativa."""

    @staticmethod
    def equals(actual: Any, expected: Any) -> bool:
        if actual is None:
            return expected is None
        return str(actual).strip().lower() == str(expected).strip().lower()

    @staticmethod
    def not_equals(actual: Any, expected: Any) -> bool:
        if actual is None:
            return False
        return not OperatorRegistry.equals(actual, expected)

    @staticmethod
    def lte(actual: Any, expected: Any) -> bool:
        try:
            return float(actual) <= float(expected)
        except (TypeError, ValueError):
            return False

    @staticmethod
    def gte(actual: Any, expected: Any) -> bool:
        try:
            return float(actual) >= float(expected)
        except (TypeError, ValueError):
            return False

    @staticmethod
    def range_inclusive(actual: Any, expected: List[Any]) -> bool:
        if not isinstance(expected, list) or len(expected) != 2:
            return False
        try:
            value = float(actual)
            return float(expected[0]) <= value <= float(expected[1])
        except (TypeError, ValueError):
            return False

    @staticmethod
    def not_regex_match(actual: Any, expected: str) -> bool:
        if actual is None:
            return False
        try:
            return re.search(expected, str(actual)) is None
        except re.error:
            return False

    @staticmethod
    def in_list(actual: Any, expected_list: List[Any]) -> bool:
        if actual is None or not isinstance(expected_list, list):
            return False
        normalized_list = [str(x).strip().lower() for x in expected_list if x is not None]
        return str(actual).strip().lower() in normalized_list

    @staticmethod
    def not_in(actual: Any, forbidden_list: List[Any]) -> bool:
        if actual is None or str(actual).strip() == "":
            return False  # Un valor ausente no puede pasar la validación
        if not isinstance(forbidden_list, list):
            return True

        normalized_list = {
            str(x).strip().lower() for x in forbidden_list if x is not None
        }
        normalized_actual = str(actual).strip().lower()
        return normalized_actual not in normalized_list

    @staticmethod
    def disjoint_tokens(actual: Union[str, List[str]], forbidden_tokens: List[str]) -> bool:
        """Verifica que ningún token prohibido esté presente en la cadena o lista actual."""
        if not actual:
            return True

        if isinstance(actual, str):
            actual_set: Set[str] = set(actual.lower().split())
        else:
            actual_set = {str(x).lower().strip() for x in actual}

        forbidden_set: Set[str] = {str(x).lower().strip() for x in forbidden_tokens if x is not None}
        return len(actual_set.intersection(forbidden_set)) == 0

    @staticmethod
    def contains_token(actual: Union[str, List[str]], expected: str) -> bool:
        if not actual:
            return False
        tokens = actual.lower().split() if isinstance(actual, str) else [str(x).lower().strip() for x in actual]
        return str(expected).lower().strip() in tokens

    @staticmethod
    def not_contains(actual: Any, expected: Any) -> bool:
        if actual is None:
            return False
        return str(expected).lower() not in str(actual or "").lower()

    @staticmethod
    def not_empty(actual: Any, expected: Any = None) -> bool:
        return actual not in (None, "", [], {}, ())

    @staticmethod
    def is_absent(actual: Any, expected: Any = None) -> bool:
        return actual in (None, "", [], {}, ())

    @staticmethod
    def not_both_contain(actual: Any, expected: Any) -> bool:
        if not isinstance(actual, dict) or not isinstance(expected, dict):
            return False
        target = str(expected.get("target_value", "")).lower()

        def contains_token(value: Any) -> bool:
            if isinstance(value, list):
                return any(contains_token(item) for item in value)
            if isinstance(value, dict):
                return any(contains_token(item) for item in value.values())
            return target in str(value).lower().split()

        return not (
            contains_token(actual.get(expected.get("field_a"), ""))
            and contains_token(actual.get(expected.get("field_b"), ""))
        )

    @staticmethod
    def contains_object(actual: Any, expected: Any) -> bool:
        if not isinstance(actual, list) or not isinstance(expected, dict):
            return False
        return any(
            isinstance(item, dict)
            and all(
                str(item.get(key, "")).strip().lower() == str(value).strip().lower()
                for key, value in expected.items()
            )
            for item in actual
        )

    @staticmethod
    def nested_property_not_in(actual: Any, forbidden: List[Any]) -> bool:
        if not isinstance(actual, list):
            return True
        forbidden_values = {str(value).lower().strip() for value in forbidden if value is not None}
        return all(
            not isinstance(item, dict) or str(item.get("name", "")).lower().strip() not in forbidden_values
            for item in actual
        )

    @staticmethod
    def subset_of(actual: List[Any], allowed_list: List[Any]) -> bool:
        if not actual:
            return True
        actual_set = {str(x).strip().lower() for x in actual}
        allowed_set = {str(x).strip().lower() for x in allowed_list}
        return actual_set.issubset(allowed_set)

    @classmethod
    def evaluate(cls, operator_name: str, actual: Any, expected: Any) -> bool:
        if operator_name == "in":
            operator_name = "in_list"
        handler = getattr(cls, operator_name, None)
        if not handler or operator_name.startswith("_") or operator_name == "evaluate":
            raise ValueError(f"Operador no soportado por el motor: '{operator_name}'")
        return handler(actual, expected)