"""Regression checks for drift between getopt and native Doxygen snippets."""

import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('check_cli_docs', ROOT / 'scripts/check_cli_docs.py')
DOCS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOCS)


class CliDocsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'src').mkdir()
        (self.root / 'doc').mkdir()
        for name in ('local.cpp', 'server.cpp', 'tunnel.cpp', 'redir.cpp', 'manager.cpp', 'utils.cpp', 'ss-nat'):
            shutil.copyfile(ROOT / 'src' / name, self.root / 'src' / name)
        for path in (ROOT / 'doc').glob('*.md'):
            shutil.copyfile(path, self.root / 'doc' / path.name)

    def change(self, filename, old, new):
        path = self.root / filename
        source = path.read_text(encoding='utf-8')
        self.assertTrue(old in source, f'Missing fixture text in {filename}')
        path.write_text(source.replace(old, new), encoding='utf-8')

    def test_current_documentation_matches_all_variants(self):
        DOCS.check(self.root)
        sources = {p.name: p.read_text(encoding='utf-8') for p in (self.root / 'src').iterdir()}
        local = DOCS.documented_options('local.cpp', sources)
        self.assertIn('-S', local)
        self.assertIn('-V', local)
        self.assertIn('--nftables-sets', DOCS.documented_options('server.cpp', sources))
        self.assertIn('-I', DOCS.documented_options('ss-nat', sources))
        self.assertNotIn('-p', DOCS.documented_options('manager.cpp', sources))

    def test_new_option_requires_documentation(self):
        self.change('src/local.cpp', '"reuse-port",', '"new-option",')
        with self.assertRaisesRegex(ValueError, 'missing documentation.*new-option'):
            DOCS.check(self.root)

    def test_argument_arity_is_checked(self):
        self.change('src/local.cpp', '"reuse-port",  no_argument',
                    '"reuse-port",  required_argument')
        with self.assertRaisesRegex(ValueError, 'argument mismatch.*reuse-port'):
            DOCS.check(self.root)

    def test_unknown_parser_syntax_fails_closed(self):
        self.change('src/local.cpp', '"reuse-port",  no_argument',
                    '"reuse-port",  optional_argument')
        with self.assertRaisesRegex(ValueError, 'Unsupported long_options'):
            DOCS.check(self.root)

    def test_nonliteral_short_options_fail_closed(self):
        self.change('src/local.cpp', '":f:s:p:l:k:t:m:i:c:b:a:n:huUv6A"', 'SHORT_OPTIONS')
        with self.assertRaisesRegex(ValueError, 'literal getopt_long'):
            DOCS.check(self.root)

    def test_shell_options_require_documentation(self):
        self.change('src/ss-nat', ':s:l:S:L:i:I:e:a:b:w:ouUfh', ':s:l:S:L:i:I:e:a:b:w:ouUfhz')
        with self.assertRaisesRegex(ValueError, 'missing documentation.*-z'):
            DOCS.check(self.root)

    def test_missing_snippet_is_rejected(self):
        self.change('src/local.cpp', 'utils.cpp cli_long_reuse_port', 'utils.cpp missing_snippet')
        with self.assertRaisesRegex(ValueError, 'Missing snippet'):
            DOCS.check(self.root)

    def test_duplicate_option_is_rejected(self):
        self.change('src/local.cpp', 'utils.cpp cli_long_reuse_port', 'utils.cpp cli_short_f')
        with self.assertRaisesRegex(ValueError, 'Duplicate documented option'):
            DOCS.check(self.root)

    def test_manual_must_include_parser_options(self):
        self.change('doc/ss-local.md', 'local.cpp cli-options', 'local.cpp missing-options')
        with self.assertRaisesRegex(ValueError, 'manual must include'):
            DOCS.check(self.root)

    def test_missing_rendered_flag_is_rejected(self):
        output = self.root / 'rendered'
        (output / 'man').mkdir(parents=True)
        (output / 'man/ss-local.1').write_text('.TH ss-local 1\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'missing rendered flag'):
            DOCS.check(self.root, output)


if __name__ == '__main__':
    unittest.main()
