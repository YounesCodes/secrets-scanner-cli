import scanner
import argparse
from pathlib import Path
import pyfiglet 
import re
import subprocess
import shutil
import os, stat
from rich.console import Console

def main():

    def scan_loop(path, args):

        findings_ascii = pyfiglet.figlet_format('Findings :')
        finding_flag = False
        all_findings = []

        if not path.exists():
            raise ValueError(f"Directory/file or repo does not exist.")

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
            print(f"No secrets found in {args.path}")
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

    # func to remove .git read-only files and avoid PermissionError
    def remove_readonly(func, path, _):
        os.chmod(path, stat.S_IWRITE)
        func(path)

    parser = argparse.ArgumentParser()
    parser.add_argument('path', nargs='?', help="File or directory to scan")
    parser.add_argument('--format', help="Define output format (json, yaml or table (default))")
    parser.add_argument('-o','--output', help="Define output file name")
    parser.add_argument('-u','--url', help="Github repo url")
    parser.add_argument('--delete', action='store_true', help="Delete repo after scan")

    args = parser.parse_args()
    url = args.url

    if args.url and not args.path:
        print("Cloning repo...")
        subprocess.run(["git", "clone","--quiet", url, "./temp_repo"])
        repo_path = Path("./temp_repo")
        print("Scanning repo...")
        scan_loop(path=repo_path, args=args)
        print("Done!")
        if args.delete:
            shutil.rmtree('./temp_repo', onerror=remove_readonly) # cross platform
            print("Repo deleted successfully.")
    elif args.path and not args.url:
        if args.delete:
            print("Error: --delete has no effect when scanning local repo.")
            return 0
        path = Path(args.path)
        print("Scanning directory...")
        scan_loop(path=path, args=args)
        print("Done!")
    else:
        parser.print_help()
        return

    

if __name__ == '__main__':
    main()
                
                
                    
                    

    



