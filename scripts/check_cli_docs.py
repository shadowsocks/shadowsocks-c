#!/usr/bin/env python3
"""Check native Doxygen CLI snippets against source getopt declarations.

This is validation only. Doxygen reads source snippets and renders the manuals;
no generated documentation or intermediate markup is written by this script.
"""

import argparse
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
PROGRAMS = ("local", "server", "tunnel", "redir", "manager", "nat")
C_COMMENT = re.compile(r'/\*.*?\*/|//[^\n]*', re.S)


def short_options(spec):
    result = {}
    spec = spec.lstrip(':+-')
    while spec:
        match = re.match(r'([A-Za-z0-9])(:?)', spec)
        if not match:
            raise ValueError(f"Unsupported getopt string: {spec}")
        flag, argument = match.groups()
        if '-' + flag in result:
            raise ValueError(f"Duplicate short option: {flag}")
        result['-' + flag] = bool(argument)
        spec = spec[match.end():]
    return result


def options(source, shell=False):
    result = {}
    if shell:
        specs = re.findall(r'^while getopts "([^"]+)" \w+; do$', source, re.M)
        if len(specs) != 1:
            raise ValueError("Expected one literal shell getopts declaration")
    else:
        source = C_COMMENT.sub('', source)
        specs = re.findall(r'getopt_long\(argc,\s*argv,\s*"([^"]+)"\s*,\s*long_options,\s*NULL\)', source)
        if not specs or len(specs) != len(re.findall(r'\bgetopt_long\s*\(', source)):
            raise ValueError("Expected literal getopt_long declarations")
    for spec in specs:
        for flag, argument in short_options(spec).items():
            if flag in result and result[flag] != argument:
                raise ValueError(f"Inconsistent argument across platform variants: {flag}")
            result[flag] = argument
    if shell:
        return result
    tables = re.findall(r'static struct option long_options\[\]\s*=\s*\{(.*?)\};', source, re.S)
    if len(tables) != 1:
        raise ValueError("Expected one long_options table")
    table = re.sub(r'^\s*#.*$', '', tables[0], flags=re.M)
    entry = re.compile(r'\{\s*"([a-z0-9-]+)"\s*,\s*(no_argument|required_argument)\s*,\s*NULL\s*,\s*(?:GETOPT_VAL_[A-Z0-9_]+|\x27[A-Za-z0-9]\x27)\s*\}\s*,', re.S)
    for match in entry.finditer(table):
        flag, argument = match.groups()
        if '--' + flag in result:
            raise ValueError(f"Duplicate long option: {flag}")
        result['--' + flag] = argument == 'required_argument'
    remainder = entry.sub('', table)
    if not re.fullmatch(r'\s*\{\s*NULL\s*,\s*0\s*,\s*NULL\s*,\s*0\s*\}\s*', remainder):
        raise ValueError(f"Unsupported long_options entry: {remainder.strip()}")
    return result



def snippets(source):
    result = {}
    for match in re.finditer(r'(?:/\*|//) \[([\w-]+)\]\n(.*?)\n\[\1\](?: \*/)?', source, re.S):
        name, body = match.groups()
        if name in result:
            raise ValueError(f"Duplicate snippet: {name}")
        result[name] = body
    return result


def documented_options(source_name, sources):
    inventory = snippets(sources[source_name]).get('cli-options')
    if not inventory:
        raise ValueError(f"{source_name}: missing cli-options snippet")
    result = {}
    for line in inventory.splitlines():
        match = re.fullmatch(r'\\snippet\{doc\} ([\w.-]+) ([\w-]+)', line)
        if not match:
            raise ValueError(f"Invalid option snippet inclusion: {line}")
        filename, identifier = match.groups()
        body = snippets(sources.get(filename, '')).get(identifier)
        if not body:
            raise ValueError(f"Missing snippet: {filename} {identifier}")
        heading, _, description = body.partition('\n')
        term = re.fullmatch(r'\\par `(-{1,2}[A-Za-z0-9][A-Za-z0-9-]*)(?: (<[^>]+>))?`', heading)
        if not term or not description.strip():
            raise ValueError(f"Invalid option documentation: {filename} {identifier}")
        flag, argument = term.groups()
        if flag in result:
            raise ValueError(f"Duplicate documented option: {flag}")
        result[flag] = bool(argument)
    return result


def module_source(sources, module):
    """Source file name for a program module; modules move from .c to .cpp."""
    for suffix in ('.c', '.cpp'):
        if module + suffix in sources:
            return module + suffix
    raise ValueError(f"No source file for module {module}")


def check(root=ROOT, rendered=None):
    sources = {path.name: path.read_text(encoding='utf-8')
               for pattern in ('*.c', '*.cpp') for path in (root / 'src').glob(pattern)}
    sources['ss-nat'] = (root / 'src/ss-nat').read_text(encoding='utf-8')
    for module in PROGRAMS:
        program = 'ss-' + module
        filename = 'ss-nat' if module == 'nat' else module_source(sources, module)
        declared = options(sources[filename], shell=module == 'nat')
        documented = documented_options(filename, sources)
        missing = declared.keys() - documented.keys()
        extra = documented.keys() - declared.keys()
        if missing or extra:
            raise ValueError(f"{program}: missing documentation {sorted(missing)}; stale documentation {sorted(extra)}")
        for flag in declared:
            if declared[flag] != documented[flag]:
                raise ValueError(f"{program}: argument mismatch for {flag}")
        page = (root / f'doc/{program}.md').read_text(encoding='utf-8')
        if page.count(f'\\snippet{{doc}} {filename} cli-options') != 1:
            raise ValueError(f"{program}: manual must include its source cli-options exactly once")
        if rendered:
            man = (rendered / 'man' / (program + '.1')).read_text(encoding='utf-8')
            man = re.sub(r'\\f[A-Z]', '', man).replace('\\-', '-')
            for flag in declared:
                if not re.search(r'(?<![\w-])' + re.escape(flag) + r'(?![\w-])', man):
                    raise ValueError(f"{program}: missing rendered flag {flag}")
            html = (rendered / 'html' / (program + '.html')).read_text(encoding='utf-8')
            if 'OPTIONS' not in html or 'SYNOPSIS' not in html:
                raise ValueError(f"{program}: incomplete HTML output")
    if rendered:
        man = (rendered / 'man/shadowsocks-c.8').read_text(encoding='utf-8')
        if not re.search(r'^\.TH .* 8 ', man, re.M):
            raise ValueError('Overview manual must use section 8')
        alias = (rendered / 'man/shadowsocks-libev.8').read_text(encoding='utf-8')
        if alias != '.so man8/shadowsocks-c.8\n':
            raise ValueError('Missing legacy manual alias')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--rendered', type=Path, help='also check a Doxygen build directory')
    args = parser.parse_args()
    try:
        check(args.root, args.rendered)
    except (ValueError, OSError) as error:
        parser.exit(1, f'{error}\n')
    print('Doxygen CLI documentation matches the source parsers.')


if __name__ == '__main__':
    main()
