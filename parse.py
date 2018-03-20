import re


def parse(acl):
    # Iterate through each line of the ACL TextIOWrapper object
    extended_count = 0
    remark_count = 0
    error_count = 0
    parsed_table = []
    errors_table = []
    for line in acl:
        result, values = parse_line(line)
        if result == 'extended':
            parsed_table.append(values[:])
            extended_count += 1
        elif result == 'remark':
            parsed_table.append(values[:])
            remark_count += 1
        elif result == 'error':
            errors_table.append(values)
            error_count += 1
    print(parsed_table)
    print(errors_table)
    print("Extended Entries : ", extended_count)
    print("Remark Entries   : ", remark_count)
    print("Parsing Errors   : ", error_count)
    print("Total Lines      : ", extended_count+remark_count+error_count)
    return parsed_table, errors_table


def parse_line(entry):
    # Parse the line
    state, values = parse_extended(entry)
    if state:
        return 'extended', values
    else:
        state, values = parse_remark(entry)
        if state:
            return 'remark', values
        else:
            values = output_error(entry)
            return 'error', values


def parse_extended(entry):
    extended = re.search(r"access-list (?P<list_name>[^\s]+) line (?P<line_number>[^\s]+) extended (?P<condition>[^\s]+) (?P<protocol>[^\s]+) (?P<src>[^\s]+) (?P<src2>[^\s]+) (?P<ent1>[^\s]+)", entry)
    if extended:
        acl_entry = [extended.group('list_name')
                    , extended.group('line_number')
                    , 'extended'
                    , ''
                    , extended.group('condition')
                    , extended.group('protocol')]
        if extended.group('src') == 'host':
            acl_entry.append(extended.group('src2'))
            acl_entry.append('255.255.255.255')
            if extended.group('src2') == 'host':
                acl_entry.append('')
                acl_entry.append('')
                acl_entry.append('')
                acl_entry.append(extended.group('ent1'))
                acl_entry.append('255.255.255.255')
            elif extended.group('src2') == 'any':
                acl_entry.append('')
                acl_entry.append('')
                acl_entry.append('')
                acl_entry.append('0.0.0.0')
                acl_entry.append('0.0.0.0')
        elif extended.group('src') == 'any':
            acl_entry.append('0.0.0.0')
            acl_entry.append('0.0.0.0')
            if extended.group('src2') == 'host':
                acl_entry.append('')
                acl_entry.append('')
                acl_entry.append('')
                acl_entry.append(extended.group('ent1'))
                acl_entry.append('255.255.255.255')
            elif extended.group('src2') == 'any':
                acl_entry.append('')
                acl_entry.append('')
                acl_entry.append('')
                acl_entry.append('0.0.0.0')
                acl_entry.append('0.0.0.0')
        else:
            acl_entry.append(extended.group('src'))
            acl_entry.append(extended.group('src2'))
        return True, acl_entry
    return False, None


def parse_remark(entry):
    remark = re.search(r"access-list (?P<list_name>[^\s]+) line (?P<line_number>[^\s]+) remark (?P<remark>.*$)", entry)
    if remark:
        acl_entry = [remark.group('list_name')
            , remark.group('line_number')
            , 'remark'
            , remark.group('remark')
            , ''
            , ''
            , ''
            , '']
        return True, acl_entry
    return False, None


def output_error(entry):
    return entry
