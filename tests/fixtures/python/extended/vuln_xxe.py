"""Vulnerable XXE patterns."""
import xml.etree.ElementTree as ET
import xml.sax


def parse_xml_file(filepath):
    """Parses XML without disabling external entities — XXE risk."""
    tree = ET.parse(filepath)
    return tree.getroot()


def parse_xml_string(xml_data):
    """Parses XML string without protection — XXE risk."""
    return ET.fromstring(xml_data)
