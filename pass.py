#!/usr/bin/env python3
"""
pass.py
Find hardcoded passwords on source code of your project.

python pass.py path/to/project

"""
import os
import sys
import re
import fnmatch
import json

from argparse import ArgumentParser

DEFAULT_BAD_WORDS = ['token', 'oauth', 'secret', 'pass', 'password', 'senha']
DEFAULT_ANALYZERS = [r' *[:=] *["\'][^"\']{4,}["\']', r'[:=][^"\'& ,;{()<\n]{4,}'] # str and url based.


def check_exclude_pattern(checkers, line):
    """Regex checker function used to ignore false positives."""
    for pattern in checkers:
        if pattern.match(line):
            return True
    return False


def can_analyze_file(include_paths, exclude_paths, path):
    """Glob checker function used to specify or ignore paths and files."""
    if include_paths and not any(fnmatch.fnmatch(path, p) for p in include_paths):
        return False

    if exclude_paths and any(fnmatch.fnmatch(path, p)for p in exclude_paths):
        return False

    return True


def build_bad_words(words):
    """Builds a regex pattern based on the bad words provided."""
    bad_words = []
    for word in words:
        rule = '(?:'
        for upper, lower in zip(word.upper(), word.lower()):
            rule += f'[{upper}{lower}]'
        rule += ')'
        bad_words.append(rule)
    return '|'.join(bad_words)


def build_regex_analyzers(rules, bad_words):
    """
    Merges the regex patterns from the bad words
    with the analyzers in order to create the
    final regex pattern to be used.
    """
    analyzers = []
    for rule in rules:
        analyzers.append(
            re.compile(f'(?:{bad_words})(?:[a-zA-Z_][a-zA-Z0-9_]*)?{rule}')
        )
    return analyzers


def check_file_handler(path, max_length, analyzers, patterns):
    """
    Check all lines of a single file.
    Also checks for max line length and for false positives.
    """
    result = []
    try:
        with open(path, 'r') as handler:
            for i, line in enumerate(handler):
                # Checking for max line length.
                if len(line) > max_length:
                    continue

                for checker in analyzers: # All analyzers run in every line.
                    data = checker.findall(line)
                    # Check if it's a false positive.
                    if data and not check_exclude_pattern(patterns, line):
                        result.append({
                            'file': path,
                            'target': data[0],
                            'line': i,
                            'string': line.strip(),
                        })

    except UnicodeDecodeError:
        # Ignore non text files.
        pass

    return result


def start_digging(root_path, limit, max_length, analyzers, patterns, include_paths, exclude_paths):
    """Start walking to all folders and subfolders in order to reach all files."""
    counter = 0
    result = []
    for root, subfolder_list, file_list in os.walk(root_path):
        for file in file_list:
            path = os.path.join(root, file)

            # Apply include/exclude glob rules.
            if not can_analyze_file(include_paths, exclude_paths, path):
                continue

            # File counter.
            if counter > limit:
                return counter, result
            counter += 1

            # Send file to be analyzed by the handler.
            result += check_file_handler(path, max_length, analyzers, patterns)

    return counter, result


if __name__ == "__main__":
    parser = ArgumentParser(description='Check for hardcoded passwords and tokens in your project.')
    parser.add_argument('--bad-words', type=open, dest='bad_words',
        help='File containing which WORDS to analyze, one word per line. \
              If not provided, will fallback to the default bad words list.'
    )
    parser.add_argument('--ignore-patterns', type=open, dest='ignore_patterns',
        help='File containing regex patterns of which TARGETS to ignore.'
    )
    parser.add_argument('--include-paths', type=open, dest='include_file',
        help='File containing glob patterns of which FILES to analyze. \
              WARNING: This option has precedence over the option "--exclude-paths".'
    )
    parser.add_argument('--exclude-paths', type=open, dest='exclude_file',
        help='File containing glob patterns of which FILES to ignore.'
    )
    parser.add_argument('--max-length', type=int, default=1000, dest='max_length',
        help='The maximun length of a line to analyze.'
    )
    parser.add_argument('--max-checks', type=int, default=sys.maxsize, dest='max_checks',
        help='Max number of files to analize.'
    )
    parser.add_argument('--json', action='store_true', dest='json',
        help='Output result in a pretty JSON format.'
    )
    parser.add_argument('path', type=str,
        help='Path to the project.'
    )
    args = parser.parse_args()

    # Preparing the bad word list.
    bad_words = []
    if args.bad_words:
        bad_words = args.bad_words.read().splitlines()
        args.bad_words.close()

    # Preparing for target patterns to ignore.
    ignore_patterns = []
    if args.ignore_patterns:
        for pattern in args.ignore_patterns:
            ignore_patterns.append(re.compile(pattern))
        args.ignore_patterns.close()

    # Checking for paths to include in the results.
    include_paths = []
    if args.include_file:
        include_paths = args.include_file.read().splitlines()
        args.include_file.close()

    # Checking for paths to exclude from results.
    exclude_paths = []
    if args.exclude_file:
        exclude_paths = args.exclude_file.read().splitlines()
        args.exclude_file.close()

    # Building bad words.
    bad_words = build_bad_words(bad_words or DEFAULT_BAD_WORDS)

    # Building regex analyzers.
    analyzers = build_regex_analyzers(DEFAULT_ANALYZERS, bad_words)

    # Start the digging!!
    counter, result = start_digging(
        args.path,
        args.max_checks,
        args.max_length,
        analyzers,
        ignore_patterns,
        include_paths,
        exclude_paths
    )

    # Outputs to JSON or to stdout.
    if args.json:
        print(json.dumps(result, indent=2))
    elif counter == 0:
        print('No file found.')
        print('STATUS: FAILED')
    else:
        for r in result:
            print('File:\t', r['file'])
            print('Line:\t', r['line'])
            print('Target:\t', r['target'], '\n')
            print(r['string'])
            print('\n--------------------------------------------------------------------------------\n')

        print('Found: {} | Files Checked: {} | (Hit Upper Limit? {})'.format(len(result), counter, 'Yes' if counter >= args.max_checks else 'No'))
        print('STATUS: {}'.format('FAILED' if result else 'OK'))

    # For CI/CD purposes.
    sys.exit(1 if result else 0)
