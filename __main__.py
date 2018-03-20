import parse
import audit
import utils
import sys
import argparse


def main():
    # Definition of Help Text
    # Argument Parsing
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description='''\
This script takes a Cisco ACL definition and parses it into a searchable spreadsheet
Automated audit rules have been included for convenience, but are disabled by default.
This is to improve execution time.
======================================================================================''')
    parser.add_argument('-o', '--out', nargs=1, help='Overwrite the name and path of the output file', default='ACL_Parsed.xlsx')
    parser.add_argument('-a', '--all', action='store_true', help='Perform all audits')
    parser.add_argument('-r', '--redundant', action='store_true', help='Perform the redundant rules audit')
    parser.add_argument('-s', '--shadow', action='store_true', help='Perform the shadowed rules audit')
    parser.add_argument('-x', '--promiscuous', action='store_true', help='Perform the promiscuous rules audit')
    parser.add_argument('infile', nargs='+', type=argparse.FileType('r'), help='Path to the ACL Definition file (.txt format)')
    args = parser.parse_args()
    # print(args)
    entries_table = []
    errors_table = []
    for acl in args.infile:
        entries, errors = parse.parse(acl)
        entries_table.append(entries[:])
        errors_table.append(errors[:])


if __name__ == "__main__":
    main()
