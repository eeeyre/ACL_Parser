from openpyxl import Workbook
from openpyxl.worksheet.table import Table, TableStyleInfo


def generate_headers(table_type):
    if table_type == 'errors':
        header = ['Parsing Errors']
    if table_type == 'rules':
        header = ['ACL Name', 'Entry Number', 'Entry Type',
                  'Remark Text', 'Permission', 'Protocol',
                  'Source IP', 'Source Mask', 'Src Port Operator',
                  'Source Port', 'Source Port Range End',
                  'Destination IP', 'Destination Mask', 'Destination Port Operator',
                  'Destination Port', 'Destination Port Range End',
                  'Hit Count', 'Check Sum']
    if table_type == 'audit':
        header = ['UnDefined Table Structure']
    return header


def output_xlsx_file(parsed_rules, errors, audit, output_file):
    wb = Workbook()
    ws1 = wb.create_sheet('Parsed')
    ws2 = wb.create_sheet('Errors')
    ws3 = wb.create_sheet('Audit')
    ws1.append(generate_headers('rules'))
    ws2.append(generate_headers('errors'))
    ws3.append(generate_headers('audit'))
    for row in parsed_rules:
        ws1.append(row)
    for row in errors:
        ws2.append(row)
    for row in audit:
        ws3.append(row)

    parsed_size = len(parsed_rules)+1  # Add one for the header
    errors_size = len(errors)+1
    audit_size = len(audit)+1

    style = TableStyleInfo(name="TableStyleMedium9", showFirstColumn=False,
                           showLastColumn=False, showRowStripes=True, showColumnStripes=True)
    parsed_tab = Table(displayName='Parsed_Rules', ref="A1:R"+str(parsed_size), TableStyleInfo=style)
    errors_tab = Table(displayName='Parsing_Errors', ref="A1:A"+str(errors_size), TableStyleInfo=style)
    audit_tab = Table(displayName='Auditing_Results', ref="A1:A"+str(audit_size), TableStyleInfo=style)

    ws1.add_table(parsed_tab)
    ws2.add_table(errors_tab)
    ws3.add_table(audit_tab)

    wb.save(output_file)



