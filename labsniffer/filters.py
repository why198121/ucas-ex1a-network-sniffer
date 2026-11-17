import json
import operator

from lark import Lark, Transformer, UnexpectedInput


GRAMMAR = r"""
?start: expression
?expression: expression "or" conjunction -> either
           | conjunction
?conjunction: conjunction "and" unary -> both
            | unary
?unary: "not" unary -> negate
      | "(" expression ")"
      | FIELD OP value -> compare
      | FIELD -> present
?value: ESCAPED_STRING -> string
      | INT -> integer
OP: "==" | "!=" | ">=" | "<=" | ">" | "<"
FIELD: /[a-z][a-z0-9_.]*/
%import common.ESCAPED_STRING
%import common.INT
%import common.WS
%ignore WS
"""

PARSER = Lark(GRAMMAR, parser="lalr", start="start")
PROTOCOLS = {"ethernet", "arp", "ip", "ipv4", "ipv6", "tcp", "udp", "icmp", "icmpv6", "dns", "http", "tls", "labdemo", "loopback", "vlan"}
NUMBER_FIELDS = {"port", "pid", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "tcp.stream",
                 "frame.number", "frame.original_number", "frame.len", "frame.caplen", "dns.id", "dns.rcode",
                 "http.status", "labdemo.type", "labdemo.request_id", "tcp.flags", "tcp.seq", "tcp.ack", "vlan.id"}
STRING_FIELDS = {"addr", "src", "dst", "ipv4.src", "ipv4.dst", "ipv6.src", "ipv6.dst", "process.name", "process.status",
                 "http.method", "http.path", "http.host", "http.version"}
BOOLEAN_FIELDS = {"frame.truncated", "ip.fragmented"}
OPERATORS = {"==": operator.eq, "!=": operator.ne, ">": operator.gt, "<": operator.lt,
             ">=": operator.ge, "<=": operator.le}


class FilterError(ValueError):
    pass


class SyntaxTree(Transformer):
    def string(self, values):
        return json.loads(str(values[0]))

    def integer(self, values):
        return int(values[0])

    def present(self, values):
        return ("present", str(values[0]))

    def compare(self, values):
        return ("compare", str(values[0]), str(values[1]), values[2])

    def both(self, values):
        return ("and", *values)

    def either(self, values):
        return ("or", *values)

    def negate(self, values):
        return ("not", values[0])


def validate(node, depth=0):
    if depth > 32:
        raise FilterError("显示过滤嵌套超过 32 层")
    kind = node[0]
    if kind in ("and", "or", "not"):
        for child in node[1:]:
            validate(child, depth + 1)
        return
    field = node[1]
    if field not in PROTOCOLS | NUMBER_FIELDS | STRING_FIELDS | BOOLEAN_FIELDS:
        raise FilterError(f"未知显示字段：{field}")
    if kind == "compare":
        value = node[3]
        if field in PROTOCOLS | BOOLEAN_FIELDS:
            raise FilterError(f"{field} 使用存在性筛选，例如 not {field}")
        if field in NUMBER_FIELDS and not isinstance(value, int):
            raise FilterError(f"{field} 需要整数")
        if field in STRING_FIELDS and not isinstance(value, str):
            raise FilterError(f"{field} 需要双引号字符串")
        if (field == "port" or field.endswith("port")) and value > 65535:
            raise FilterError("端口范围为 0–65535")


def matches(node, fields):
    kind = node[0]
    if kind == "and":
        return matches(node[1], fields) and matches(node[2], fields)
    if kind == "or":
        return matches(node[1], fields) or matches(node[2], fields)
    if kind == "not":
        return not matches(node[1], fields)
    value = fields.get(node[1])
    if kind == "present":
        return value is not None and value is not False and value != [] and value != ""
    if value is None:
        return False
    values = value if isinstance(value, (list, tuple)) else [value]
    comparator = OPERATORS[node[2]]
    checks = [comparator(item, node[3]) for item in values]
    return bool(checks) and (all(checks) if node[2] == "!=" else any(checks))


def compile_filter(expression):
    if not expression.strip():
        return lambda packet: True
    if len(expression) > 1024:
        raise FilterError("显示过滤长度超过 1024 字符")
    if expression.count("(") > 32:
        raise FilterError("显示过滤括号过多")
    try:
        tree = SyntaxTree().transform(PARSER.parse(expression))
    except UnexpectedInput as error:
        raise FilterError(f"显示过滤语法错误，第 {error.column} 列；字符串需要双引号") from error
    validate(tree)
    return lambda packet: matches(tree, packet.fields)
