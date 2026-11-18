import pytest

from security.xml_parser import (
    parse_orders,
    has_doctype,
    has_external_entity,
    safe_external_url,
    entity_count_ok,
    namespace_ok
)


def test_simple():
    assert len(parse_orders('<orders><order id="1"/></orders>')) == 1

def test_doctype():
    assert has_doctype('<!DOCTYPE orders>') is True

def test_external():
    assert has_external_entity('<!ENTITY x SYSTEM "file:///etc/passwd">') is True

def test_xinclude():
    assert has_external_entity('<xi:include href="http://evil"/>') is True

def test_entity_limit():
    assert entity_count_ok('&a;' * 10, 5) is False

def test_url_ok():
    assert safe_external_url('https://schema.example/x.xsd', {'schema.example'}) is True

def test_url_internal():
    assert safe_external_url('http://127.0.0.1/x.xsd', {'schema.example'}) is False

def test_namespace():
    assert namespace_ok('<o:orders xmlns:o="urn:o"><o:order/></o:orders>', 'urn:o') is True

def test_malformed():
    assert parse_orders('<orders>') == []

def test_cdata():
    assert len(parse_orders('<orders><order><note><![CDATA[x<y]]></note></order></orders>')) == 1

def test_empty():
    assert parse_orders('') == []

def test_entity_recursion():
    assert entity_count_ok('&a;&a;', 1) is False

def test_no_doctype():
    assert has_doctype('<orders/>') is False

def test_doctype_system():
    assert has_external_entity('<!DOCTYPE x SYSTEM "http://evil">') is True

def test_namespace_bad():
    assert namespace_ok('<o:orders xmlns:o="urn:evil"/>', 'urn:o') is False
