import utils
import ipaddress


def audit(entries_table, audit_type):
    audit_table = []
    audit_bool = audit_type[0] or audit_type[1]
    if audit_type[2]:
        print("Shadowed Rules Audit Not Implemented.")
    if audit_bool:
        for acl in entries_table:
            for entry in acl:
                if audit_type[0]:
                    error = audit_promiscuous(entry)
                    if error:
                        audit_table.append(error)
                if audit_type[1]:
                    error = audit_redundant(entry, acl)
                    if error:
                        audit_table.append(error)
                if audit_type[2]:
                    error = audit_shadowed(entry, acl)
                    if error:
                        audit_table.append(error)
    return audit_table


def audit_promiscuous(entry):
    # Define IP Address Information
    max_class_a = 2147483647
    max_class_b = 3221225471
    max_class_c = 3758096383
    class_c_subnet = 4294967040
    class_b_subnet = 4294901760
    class_a_subnet = 4278190080

    acl_name = entry[0]
    entry_number = entry[1]
    violation_type = 'Promiscuous'
    source_class = ''
    dest_class = ''
    large_source = False
    large_dest = False
    violation_desc = ''

    try:
        subnet = int(ipaddress.ip_address(entry[6]))
        mask = int(ipaddress.ip_address(entry[7]))
        if subnet <= max_class_a and mask <= class_a_subnet:
            source_class = 'Class A'
            large_source = True
        elif max_class_a < subnet <= max_class_b and mask <= class_b_subnet:
            source_class = 'Class B'
            large_source = True
        elif max_class_b < subnet <= max_class_c and mask <= class_c_subnet:
            source_class = 'Class C'
            large_source = True
        subnet = int(ipaddress.ip_address(entry[11]))
        mask = int(ipaddress.ip_address(entry[12]))
        if subnet <= max_class_a and mask <= class_a_subnet:
            dest_class = 'Class A'
            large_dest = True
        elif max_class_a < subnet <= max_class_b and mask <= class_b_subnet:
            dest_class = 'Class B'
            large_dest = True
        elif max_class_b < subnet <= max_class_c and mask <= class_c_subnet:
            dest_class = 'Class C'
            large_dest = True

    except ValueError:
        pass

    if entry[2] == 'remark':
        return None
    # Alert on the use of the Any Keyword
    if entry[6] == '0.0.0.0' and entry[7] == '0.0.0.0':
        violation_desc = utils.add_desc(violation_desc, 'Any Keyword in Source')
    if entry[11] == '0.0.0.0' and entry[12] == '0.0.0.0':
        violation_desc = utils.add_desc(violation_desc, 'Any Keyword in Destination')
    if entry[9] == '':
        violation_desc = utils.add_desc(violation_desc, 'Unspecified Source Port')
    if entry[14] == '':
        violation_desc = utils.add_desc(violation_desc, 'Unspecified Destination Port')
    # Check if the subnet is greater than the classful designation
    if large_source:
        violation_desc = utils.add_desc(violation_desc, 'Source Subnet Larger than ' + source_class)
    if large_dest:
        violation_desc = utils.add_desc(violation_desc, 'Destination Subnet Larger than ' + dest_class)
    if violation_desc != '':
        return [acl_name, entry_number, violation_type, violation_desc]

    return None


def audit_redundant(entry, acl):
    acl_name = entry[0]
    entry_number = entry[1]
    violation_type = 'Redundant'
    violation_desc = ''
    for line in acl:
        if entry[0] != line[0]:  # Skip if the ACL Name doesn't match
            continue
        elif entry[0] == line[0] \
                and entry[1] > line[1] \
                and entry[2] != 'remark' \
                and entry[5] == line[5] \
                and entry[6] == line[6] \
                and entry[7] == line[7] \
                and entry[8] == line[8] \
                and entry[9] == line[9] \
                and entry[11] == line[11] \
                and entry[12] == line[12]:
            if violation_desc == '':
                violation_desc = utils.add_desc(violation_desc,
                                    'Rule Possibly Made Redundant by Entry Lines: ' + line[1])
            else:
                violation_desc = utils.add_desc(violation_desc, line[1])
    if violation_desc == '':
        return None
    return [acl_name, entry_number, violation_type, violation_desc]


def audit_shadowed(entry, acl):
    return None
