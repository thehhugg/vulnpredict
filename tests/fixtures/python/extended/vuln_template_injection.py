"""Vulnerable template injection patterns."""
import jinja2


def render_user_template(user_input):
    """Renders user-provided template string — SSTI risk."""
    env = jinja2.Environment()
    template = jinja2.Template(user_input)
    return template.render()
