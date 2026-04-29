from . import utils
import argparse
from pathlib import Path
import subprocess
import shutil
import os, stat

def main():
    def scan_loop(path, args):
        all_findings = []

        if not path.exists():
            raise ValueError(f"Directory/file or repo does not exist.")

        if path.is_file():
            with open(path,'r', errors='ignore') as f:
                content = f.read()
                findings = utils.scan_content(content, path)
                all_findings.extend(findings)
        else:
            for item in path.rglob('*'):
                if not utils.should_ignore(item):
                    if item.is_file():
                        with open(item, 'r', errors='ignore') as f:
                            content = f.read()
                            findings = utils.scan_content(content, item)
                            all_findings.extend(findings)

        if not all_findings:
            print(f"No secrets found in {path}")
        else:
            if args.output and args.format:
                utils.export_findings(findings=all_findings, output_file_name=args.output)
                utils.print_findings(findings=all_findings,output_format=args.format,filepath=path)
                print(f"Findings saved in {args.output}")
            elif args.output and not args.format:
                utils.export_findings(findings=all_findings, output_file_name=args.output)
                print(f"Findings saved in {args.output}")
            elif not args.output and args.format:
                utils.print_findings(findings=all_findings,output_format=args.format,filepath=path)
            else:
                utils.print_findings(findings=all_findings,output_format='table',filepath=path)

    # func to remove .git read-only files and avoid PermissionError
    def remove_readonly(func, path, _):
        os.chmod(path, stat.S_IWRITE)
        func(path)

    parser = argparse.ArgumentParser(prog="secrets-scan", description="Detect hardcoded secrets and credentials in source code.")
    parser.add_argument('path', nargs='?', help="File or directory to scan (local path)")
    parser.add_argument('--format', choices=["table", "json", "yaml"], default="table", help="Output format: table (default), json, yaml")
    parser.add_argument('-o','--output', metavar="FILE", help="Write results to file (e.g. results.json). Requires --format json or yaml")
    parser.add_argument('-u','--url', metavar="URL", help="GitHub repo URL to clone and scan")
    parser.add_argument('--delete', action='store_true', help="Delete cloned repo after scan (use with --url)")

    args = parser.parse_args()

    if args.url and not args.path:
        print("Cloning repo...")
        subprocess.run(["git", "clone","--quiet", args.url])
        repo_name = args.url.rstrip("/").split("/")[-1].removesuffix(".git")
        repo_path = Path(repo_name)
        print("Scanning repo...")
        scan_loop(path=repo_path, args=args)
        print("Done!")
        if args.delete:
            shutil.rmtree(repo_name, onerror=remove_readonly) # cross platform
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
                
                
                    
                    

    



