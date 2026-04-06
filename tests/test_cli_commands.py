"""Tests for CLI command extension hooks in ExtensionRegistry."""

import unittest

from lumen_argus.extensions import CliCommandDef, ExtensionRegistry


class TestCLICommandExtension(unittest.TestCase):
    """Test CLI command extension hooks in ExtensionRegistry."""

    def test_register_and_retrieve(self):
        reg = ExtensionRegistry()
        self.assertEqual(reg.get_extra_cli_commands(), [])

        commands = [
            CliCommandDef(
                name="enroll",
                help="Enroll this machine",
                arguments=[
                    {"args": ["--server"], "kwargs": {"default": "", "help": "Proxy URL"}},
                ],
                handler=lambda args: None,
            ),
            CliCommandDef(
                name="enrollment",
                help="Manage enrollments",
                handler=lambda args: None,
            ),
        ]
        reg.register_cli_commands(commands)
        result = reg.get_extra_cli_commands()
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].name, "enroll")
        self.assertEqual(result[1].name, "enrollment")

    def test_returns_copy(self):
        reg = ExtensionRegistry()
        reg.register_cli_commands([CliCommandDef(name="test", handler=lambda a: None)])
        first = reg.get_extra_cli_commands()
        first.clear()
        self.assertEqual(len(reg.get_extra_cli_commands()), 1)

    def test_multiple_registrations_accumulate(self):
        reg = ExtensionRegistry()
        reg.register_cli_commands([CliCommandDef(name="cmd1", handler=lambda a: None)])
        reg.register_cli_commands([CliCommandDef(name="cmd2", handler=lambda a: None)])
        self.assertEqual(len(reg.get_extra_cli_commands()), 2)

    def test_rejects_dict(self):
        reg = ExtensionRegistry()
        with self.assertRaises(TypeError):
            reg.register_cli_commands([{"name": "bad", "handler": lambda a: None}])

    def test_rejects_empty_name(self):
        reg = ExtensionRegistry()
        with self.assertRaises(ValueError):
            reg.register_cli_commands([CliCommandDef(name="", handler=lambda a: None)])

    def test_rejects_non_callable_handler(self):
        reg = ExtensionRegistry()
        with self.assertRaises(ValueError):
            reg.register_cli_commands([CliCommandDef(name="broken", handler="not_callable")])


if __name__ == "__main__":
    unittest.main()
