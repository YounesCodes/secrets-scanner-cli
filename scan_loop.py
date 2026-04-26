import scanner
import argparse
import pprint
from pathlib import Path
import pyfiglet 
import re

findings_ascii = pyfiglet.figlet_format('Findings :')
finding_flag = False
results = {}

parser = argparse.ArgumentParser()
parser.add_argument('filename')
parser.add_argument('--format')
parser.add_argument('--output')

args = parser.parse_args()

path = Path(args.filename)

if not finding_flag:
    if not args.output:
        #print(args.format)
        print(findings_ascii)
        finding_flag = True

for item in path.rglob('*'):
    if not scanner.should_ignore(item):
        if item.is_file():
            with open(item, 'r') as f:
                content = f.read()
                lines = content.splitlines()
                findings = scanner.scan_content(content, lines)
                #print(findings)
                if findings:
                    if args.output:
                        scanner.export_findings(findings=findings, output_file_name=args.output)
                    elif not args.format or args.format == 'table':
                        scanner.print_findings_table(findings=findings, filepath=item)
                    elif args.format == 'json':
                        scanner.print_findings_json(findings=findings, filepath=item)
                    elif args.format == 'yaml':
                        scanner.print_findings_yaml(findings=findings, filepath=item)



                
                
                    
                    

    



