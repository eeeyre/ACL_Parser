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
    # print(parsed_table)
    # print(errors_table)
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
    extended = re.search(r"access-list (?P<list_name>[^\s]+) "
                         r"line (?P<line_number>[^\s]+) "
                         r"extended (?P<condition>[^\s]+) "
                         r"(?P<protocol>[^\s]+) "
                         r"(?P<remainder>.*$)"
                         , entry)
    if extended:
        src_ip, src_mask, remainder = get_ip_info(extended.group('remainder'))
        src_port_cond, src_port, src_port_range_end, remainder = get_port_info(remainder)
        dest_ip, dest_mask, remainder = get_ip_info(remainder)
        dest_port_cond, dest_port, dest_port_range_end, remainder = get_port_info(remainder)

        conclusion = re.search(r".*\(hitcnt=(?P<hitcount>[^)]+)\) (?P<checksum>.*) ", remainder)
        conclusion_no_hitcount = re.search(r".*(?P<checksum>0x.*)", remainder)
        if conclusion:
            hitcount = conclusion.group('hitcount')
            checksum = conclusion.group('checksum')
        elif conclusion_no_hitcount:
            hitcount = ''
            checksum = conclusion_no_hitcount.group('checksum')
        else:
            return False, None
        acl_entry = [
            extended.group('list_name'),
            extended.group('line_number'),
            'extended', '',
            extended.group('condition'),
            extended.group('protocol'),
            src_ip, src_mask,
            src_port_cond, src_port, src_port_range_end,
            dest_ip, dest_mask,
            dest_port_cond, dest_port, dest_port_range_end,
            hitcount, checksum
        ]
        # print(acl_entry)
        return True, acl_entry
    else:
        return False, None


def get_ip_info(entry):
    ip_info = re.split(" ", entry, 4)
    if ip_info[0] == 'host':
        ip = ip_info[1]
        subnet = '255.255.255.255'
        del ip_info[:2]
        remainder = " ".join(ip_info)
    elif ip_info[0] == 'any':
        ip = '0.0.0.0'
        subnet = '0.0.0.0'
        del ip_info[:1]
        remainder = " ".join(ip_info)
    elif ip_info[0] == 'fqdn':
        ip = ip_info[1]
        subnet = 'fqdn'
        del ip_info[:3]
        remainder = " ".join(ip_info)
    else:  # This will be ips and object groups.
        ip = ip_info[0]
        subnet = ip_info[1]
        del ip_info[:2]
        remainder = " ".join(ip_info)
    return ip, subnet, remainder


def get_port_info(entry):
    port_info = re.split(" ", entry, 4)
    if (port_info[0] == 'eq') or (port_info[0] == 'gt') or (port_info[0] == 'lt'):
        port_comp = port_info[0]
        port = port_info[1]
        port_range_end = ''
        del port_info[:2]
        remainder = " ".join(port_info)
    elif port_info[0] == 'range':
        port_comp = port_info[0]
        port = port_info[1]
        port_range_end = port_info[2]
        del port_info[:3]
        remainder = " ".join(port_info)
    else:
        port_comp = ''
        port = ''
        port_range_end = ''
        remainder = entry
    return port_comp, port, port_range_end, remainder


def parse_remark(entry):
    remark = re.search(r"access-list (?P<list_name>[^\s]+) line (?P<line_number>[^\s]+) remark (?P<remark>.*$)", entry)
    if remark:
        acl_entry = [remark.group('list_name')
            , remark.group('line_number')
            , 'remark'
            , remark.group('remark')
            , '', '', '', '', '', '', '', '', '', '', '', '', '', '']
        return True, acl_entry
    return False, None


def output_error(entry):
    return entry
