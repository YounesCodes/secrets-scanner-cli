import scanner
import argparse
import pprint
from pathlib import Path
import pyfiglet 
import re

def main():
    findings_ascii = pyfiglet.figlet_format('Findings :')
    finding_flag = False
    all_findings = []

    parser = argparse.ArgumentParser()
    parser.add_argument('directory')
    parser.add_argument('--file')
    parser.add_argument('--format')
    parser.add_argument('--output')

    args = parser.parse_args()
    path = Path(args.directory)
    
    if not path.exists():
        raise ValueError(f"Directory/file does not exist.")
        return 0 

    if path.is_file():
        with open(path,'r') as f:
            content = f.read()
            findings = scanner.scan_content(content, path)
            all_findings.extend(findings)
    else:
        for item in path.rglob('*'):
            if not scanner.should_ignore(item):
                if item.is_file():
                    with open(item, 'r') as f:
                        content = f.read()
                        findings = scanner.scan_content(content, item)
                        all_findings.extend(findings)

    if not all_findings:
        print(f"No secrets found in {args.directory}")
        return 1
    else:
        if args.output:
            scanner.export_findings(findings=all_findings, output_file_name=args.output)
            print(f"Findings saved in {args.output}")
        elif not args.format or args.format == 'table':
            print(findings_ascii)
            scanner.print_findings_table(findings=all_findings, filepath=path)
        elif args.format == 'json':
            print(findings_ascii)
            scanner.print_findings_json(findings=all_findings)
        elif args.format == 'yaml':
            print(findings_ascii)
            scanner.print_findings_yaml(findings=all_findings)
        else:
            raise ValueError(f"Invalid --format flag value, available formats: json,yaml,table (default).")
    return 1

if __name__ == '__main__':
    main()
                
                
                    
                    

    



