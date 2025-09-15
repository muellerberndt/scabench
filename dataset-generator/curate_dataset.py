#!/usr/bin/env python3
"""
Curate ScaBench dataset based on specific criteria:
1. At least one existing GitHub repo (not returning 404)
2. At least 5 total vulnerabilities
3. At least 1 high or critical finding
4. Run cloc on repositories (optional - if fails, project is still included)
"""

import json
import subprocess
import sys
import os
import tempfile
import shutil
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict
import urllib.request
import urllib.error

# Simple console output without rich
class SimpleConsole:
    def print(self, msg):
        # Extract text from rich markup
        import re
        clean_msg = re.sub(r'\[.*?\]', '', msg)
        print(clean_msg)

console = SimpleConsole()


@dataclass
class ProjectStats:
    """Statistics for a curated project."""
    project_name: str
    audit_url: str
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    available_repo: str
    cloc_stats: Dict[str, Any]


def check_github_repo(url: str) -> bool:
    """Check if a GitHub repository is accessible (not 404)."""
    try:
        # Simply check if the repo URL itself is accessible
        # This avoids API rate limits and authentication
        if "github.com" in url:
            # Clean up the URL
            clean_url = url.replace(".git", "")
            if not clean_url.startswith("http"):
                clean_url = "https://" + clean_url
                
            request = urllib.request.Request(clean_url)
            request.add_header('User-Agent', 'Mozilla/5.0 (compatible; ScaBench-Curator/1.0)')
            
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    # GitHub returns 200 for valid repos
                    return response.status == 200
            except urllib.error.HTTPError as e:
                # 404 means repo doesn't exist
                return e.code != 404
            except urllib.error.URLError:
                # Network error - assume repo might exist
                return True
        return False
    except Exception as e:
        # On error, assume repo might exist to avoid false negatives
        return True


def fix_code4rena_findings_url(url: str) -> str:
    """
    Fix Code4rena findings URLs by converting them to actual code repos.
    Changes: https://github.com/code-423n4/2024-10-superposition-findings
    To: https://github.com/code-423n4/2024-10-superposition
    """
    if "code-423n4" in url and url.endswith("-findings"):
        return url[:-9]  # Remove "-findings" suffix
    return url


def get_first_available_repo(codebases: List[Any]) -> Optional[str]:
    """Find the first available (non-404) GitHub repository from a list."""
    valid_repos = []
    
    for codebase in codebases:
        # Handle both string URLs and dictionary objects
        if isinstance(codebase, str):
            repo_url = codebase
        elif isinstance(codebase, dict):
            repo_url = codebase.get("repo_url", "")
        else:
            continue
            
        # Skip media-kit repos and other non-code repos
        if "media-kit" in repo_url.lower():
            continue
        if "docs" in repo_url.lower() and "documentation" in repo_url.lower():
            continue
            
        if repo_url and "github.com" in repo_url:
            # Fix Code4rena findings URLs
            repo_url = fix_code4rena_findings_url(repo_url)
            
            # Check if the repo actually exists (not 404)
            if check_github_repo(repo_url):
                valid_repos.append(repo_url)
    
    # Prioritize audit platform repos (code-423n4, sherlock, etc)
    audit_platforms = ["code-423n4", "sherlock-audit", "cantina-xyz"]
    for repo_url in valid_repos:
        if any(platform in repo_url for platform in audit_platforms):
            return repo_url
    
    # Fall back to first valid repo
    if valid_repos:
        return valid_repos[0]
    
    return None


def count_vulnerabilities_by_severity(vulnerabilities: List[Dict]) -> Tuple[int, int, int, int]:
    """Count vulnerabilities by severity level."""
    critical = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "critical")
    high = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high")
    medium = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium")
    low = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")
    
    return critical, high, medium, low


def run_cloc_on_repo(repo_url: str) -> Dict[str, Any]:
    """Clone repository temporarily and run cloc on it."""
    cloc_stats = {
        "total_files": 0,
        "total_lines": 0,
        "solidity_files": 0,
        "solidity_lines": 0,
        "error": None
    }
    
    # Create temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Clone the repository
            clone_path = Path(temp_dir) / "repo"
            print(f"    Cloning and analyzing repository...", end=" ")
            
            result = subprocess.run(
                ["git", "clone", "--depth", "1", "-q", repo_url, str(clone_path)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                cloc_stats["error"] = f"Clone failed"
                print("failed")
                return cloc_stats
            
            # Run cloc
            result = subprocess.run(
                ["cloc", "--json", "--quiet", "--exclude-dir=test,tests", str(clone_path)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print("done")
                try:
                    cloc_data = json.loads(result.stdout)
                    
                    # Extract total stats
                    if "SUM" in cloc_data:
                        cloc_stats["total_files"] = cloc_data["SUM"].get("nFiles", 0)
                        cloc_stats["total_lines"] = cloc_data["SUM"].get("code", 0)
                    
                    # Extract Solidity stats
                    if "Solidity" in cloc_data:
                        cloc_stats["solidity_files"] = cloc_data["Solidity"].get("nFiles", 0)
                        cloc_stats["solidity_lines"] = cloc_data["Solidity"].get("code", 0)
                    
                    # Store full breakdown
                    cloc_stats["languages"] = {
                        lang: {
                            "files": data.get("nFiles", 0),
                            "lines": data.get("code", 0)
                        }
                        for lang, data in cloc_data.items()
                        if lang not in ["header", "SUM"]
                    }
                    
                except json.JSONDecodeError:
                    print("failed (parse error)")
                    cloc_stats["error"] = "Failed to parse cloc output"
            else:
                print("failed")
                cloc_stats["error"] = f"cloc failed"
                
        except subprocess.TimeoutExpired:
            cloc_stats["error"] = "Operation timed out"
        except Exception as e:
            cloc_stats["error"] = str(e)
    
    return cloc_stats


def meets_criteria(entry: Dict[str, Any], min_vulnerabilities: int = 5, min_high_critical: int = 1) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Check if an entry meets all criteria.
    
    Args:
        entry: The project entry to check
        min_vulnerabilities: Minimum number of total vulnerabilities required
        min_high_critical: Minimum number of high or critical vulnerabilities required
    
    Returns:
        (meets_criteria, reason, stats)
    """
    stats = {}
    
    # Check for codebases
    codebases = entry.get("codebases", [])
    if not codebases:
        return False, "No codebases listed", stats
    
    # Check for existing (non-404) GitHub repo
    available_repo = get_first_available_repo(codebases)
    if not available_repo:
        return False, "No existing GitHub repository (all repos returned 404)", stats
    
    stats["available_repo"] = available_repo
    
    # Count vulnerabilities
    vulnerabilities = entry.get("vulnerabilities", [])
    total_vulns = len(vulnerabilities)
    
    if total_vulns < min_vulnerabilities:
        return False, f"Only {total_vulns} vulnerabilities (need {min_vulnerabilities}+)", stats
    
    # Count by severity
    critical, high, medium, low = count_vulnerabilities_by_severity(vulnerabilities)
    
    stats["total_vulnerabilities"] = total_vulns
    stats["critical_count"] = critical
    stats["high_count"] = high
    stats["medium_count"] = medium
    stats["low_count"] = low
    
    # Check for minimum high or critical
    if critical + high < min_high_critical:
        return False, f"Only {critical + high} high/critical vulnerabilities (need {min_high_critical}+)", stats
    
    return True, "Meets all criteria", stats


def generate_report(project_stats: List[ProjectStats], total_projects: int, output_path: Path, min_vulnerabilities: int = 5, min_high_critical: int = 1):
    """Generate a detailed report of the curation process."""
    
    # Calculate retention rate safely
    retention_rate = (len(project_stats) / total_projects * 100) if total_projects > 0 else 0
    
    report_lines = [
        "# ScaBench Dataset Curation Report",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        f"- Total projects in original dataset: {total_projects}",
        f"- Projects meeting criteria: {len(project_stats)}",
        f"- Retention rate: {retention_rate:.1f}%",
        "",
        "## Criteria Applied",
        "1. At least one existing GitHub repository (not returning 404)",
        f"2. At least {min_vulnerabilities} total vulnerabilities",
        f"3. At least {min_high_critical} high or critical finding(s)",
        "4. CLOC statistics added when repository can be cloned (optional)",
        "",
        "## Selected Projects",
        ""
    ]
    
    # Add table of selected projects
    for i, stats in enumerate(project_stats, 1):
        report_lines.extend([
            f"### {i}. {stats.project_name}",
            f"- **Audit URL**: {stats.audit_url}",
            f"- **Repository**: {stats.available_repo}",
            f"- **Vulnerabilities**: {stats.total_vulnerabilities} total "
            f"(Critical: {stats.critical_count}, High: {stats.high_count}, "
            f"Medium: {stats.medium_count}, Low: {stats.low_count})",
            ""
        ])
        
        if stats.cloc_stats and not stats.cloc_stats.get("error"):
            report_lines.extend([
                "#### Code Statistics",
                f"- **Total Files**: {stats.cloc_stats['total_files']:,}",
                f"- **Total Lines**: {stats.cloc_stats['total_lines']:,}",
                f"- **Solidity Files**: {stats.cloc_stats['solidity_files']:,}",
                f"- **Solidity Lines**: {stats.cloc_stats['solidity_lines']:,}",
                ""
            ])
            
            if "languages" in stats.cloc_stats:
                report_lines.append("#### Language Breakdown")
                for lang, data in sorted(stats.cloc_stats["languages"].items(), 
                                        key=lambda x: x[1]["lines"], reverse=True)[:5]:
                    report_lines.append(f"- {lang}: {data['lines']:,} lines ({data['files']} files)")
                report_lines.append("")
        elif stats.cloc_stats.get("error"):
            report_lines.extend([
                "#### Code Statistics",
                f"- Error: {stats.cloc_stats['error']}",
                ""
            ])
    
    # Add aggregate statistics
    total_lines = sum(
        s.cloc_stats.get("total_lines", 0) 
        for s in project_stats 
        if s.cloc_stats and not s.cloc_stats.get("error")
    )
    
    total_solidity_lines = sum(
        s.cloc_stats.get("solidity_lines", 0) 
        for s in project_stats 
        if s.cloc_stats and not s.cloc_stats.get("error")
    )
    
    total_files = sum(
        s.cloc_stats.get("total_files", 0) 
        for s in project_stats 
        if s.cloc_stats and not s.cloc_stats.get("error")
    )
    
    total_vulns = sum(s.total_vulnerabilities for s in project_stats)
    total_critical = sum(s.critical_count for s in project_stats)
    total_high = sum(s.high_count for s in project_stats)
    
    # Calculate average only if there are projects
    avg_vulns = total_vulns / len(project_stats) if project_stats else 0
    
    report_lines.extend([
        "## Aggregate Statistics",
        f"- **Total Lines of Code (all languages)**: {total_lines:,}",
        f"- **Total Solidity Lines**: {total_solidity_lines:,}",
        f"- **Total Files**: {total_files:,}",
        f"- **Total Vulnerabilities**: {total_vulns:,}",
        f"- **Total Critical**: {total_critical:,}",
        f"- **Total High**: {total_high:,}",
        f"- **Average Vulnerabilities per Project**: {avg_vulns:.1f}",
        ""
    ])
    
    # Write report
    with open(output_path, "w") as f:
        f.write("\n".join(report_lines))


def main():
    """Main curation process."""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Curate ScaBench dataset based on specific criteria")
    parser.add_argument(
        "-i", "--input",
        type=str,
        required=True,
        help="Path to input JSON dataset file"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        required=True,
        help="Path to output curated JSON file"
    )
    parser.add_argument(
        "-r", "--report",
        type=str,
        default="curation_report.md",
        help="Path to output report file (default: curation_report.md)"
    )
    parser.add_argument(
        "--min-vulnerabilities",
        type=int,
        default=5,
        help="Minimum number of total vulnerabilities required (default: 5)"
    )
    parser.add_argument(
        "--min-high-critical",
        type=int,
        default=1,
        help="Minimum number of high or critical vulnerabilities required (default: 1)"
    )
    parser.add_argument(
        "--language",
        type=str,
        default=None,
        help="Filter projects by a specific language (e.g., Solidity, Rust)"
    )
    
    args = parser.parse_args()
    
    # Load the dataset
    dataset_path = Path(args.input)
    
    if not dataset_path.exists():
        console.print(f"[red]Error: Dataset not found at {dataset_path}[/red]")
        sys.exit(1)
    
    console.print(f"[bold cyan]Loading dataset from {dataset_path}[/bold cyan]")
    
    with open(dataset_path, "r") as f:
        data = json.load(f)
    
    # Extract projects array from the dataset
    dataset = data.get("projects", [])
    
    console.print(f"[green]Loaded {len(dataset)} projects from {data.get('dataset_id', 'unknown')}[/green]")
    
    # Check if cloc is installed
    if shutil.which("cloc") is None:
        console.print("[yellow]Warning: cloc is not installed. Install with: brew install cloc[/yellow]")
        console.print("[yellow]Continuing without code statistics...[/yellow]")
    
    # Process each entry
    curated_entries = []
    project_stats_list = []
    
    console.print(f"Processing {len(dataset)} projects...")
    
    for i, entry in enumerate(dataset, 1):
        project_name = entry.get("name", entry.get("project_id", "Unknown"))
        print(f"[{i}/{len(dataset)}] Processing {project_name}...", end=" ")
        
        meets, reason, stats = meets_criteria(entry, args.min_vulnerabilities, args.min_high_critical)
        
        if meets:
            print(f"✓ {reason}")
            print(f"  Repo: {stats['available_repo']}")
            print(f"  Vulnerabilities: {stats['total_vulnerabilities']} total (Critical: {stats['critical_count']}, High: {stats['high_count']}, Medium: {stats['medium_count']}, Low: {stats['low_count']})")
            
            # Run cloc if available
            if shutil.which("cloc") and stats.get("available_repo"):
                cloc_stats = run_cloc_on_repo(stats["available_repo"])
                
                # Print cloc results
                if not cloc_stats.get("error"):
                    print(f"  Code Statistics:")
                    print(f"    - Total Files: {cloc_stats.get('total_files', 0):,}")
                    print(f"    - Total Lines: {cloc_stats.get('total_lines', 0):,}")
                    
                    # Smart contract languages to highlight
                    smart_contract_langs = ["Solidity", "Rust", "Go", "Move", "Cairo", "Vyper", "Yul", "C++", "C"]
                    
                    # Show smart contract languages found
                    if "languages" in cloc_stats and cloc_stats["languages"]:
                        sc_langs_found = []
                        for lang in smart_contract_langs:
                            if lang in cloc_stats["languages"]:
                                lang_data = cloc_stats["languages"][lang]
                                sc_langs_found.append((lang, lang_data["lines"], lang_data["files"]))
                        
                        if sc_langs_found:
                            print(f"    - Smart Contract Languages:")
                            for lang, lines, files in sorted(sc_langs_found, key=lambda x: x[1], reverse=True):
                                print(f"      • {lang}: {lines:,} lines in {files} files")
                        
                        # Show other top languages
                        other_langs = [(lang, data) for lang, data in cloc_stats["languages"].items() 
                                      if lang not in smart_contract_langs]
                        if other_langs:
                            top_other = sorted(other_langs, key=lambda x: x[1]["lines"], reverse=True)[:3]
                            if top_other:

                                other_langs_str = ", ".join([f"{lang}: {data['lines']:,}" for lang, data in top_other])
                                print(f"    - Other Languages: {other_langs_str}")

                    print(f"  Code Statistics: Error - {cloc_stats['error']}")
            else:
                cloc_stats = {"error": "cloc not available"}
                print(f"  Code Statistics: Skipped (cloc not available)")
            
            print()  # Add blank line for readability
            
            # Create project stats
            project_stat = ProjectStats(
                project_name=project_name,
                audit_url=entry.get("audit_url", entry.get("platform", "") + "/" + entry.get("project_id", "")),
                total_vulnerabilities=stats["total_vulnerabilities"],
                critical_count=stats["critical_count"],
                high_count=stats["high_count"],
                medium_count=stats["medium_count"],
                low_count=stats["low_count"],
                available_repo=stats["available_repo"],
                cloc_stats=cloc_stats
            )
            
            # Add language to the entry
            primary_language = None
            # Whitelist of non-programming languages to ignore
            language_whitelist = {"json", "html", "markdown", "css", "yaml", "toml", "xml", "shell", "text", "typescript", "javascript", "svg"}
            
            if "languages" in cloc_stats and cloc_stats["languages"]:
                sorted_langs = sorted(cloc_stats["languages"].items(), key=lambda x: x[1]["lines"], reverse=True)
                
                # Find the first language not in the whitelist
                for lang, _ in sorted_langs:
                    if lang.lower() not in language_whitelist:
                        primary_language = lang
                        entry["language"] = primary_language
                        break
            
            # Filter by language if specified
            if args.language:
                if not primary_language or primary_language.lower() != args.language.lower():
                    print(f"  Language Mismatch: Skipping project with language '{primary_language}'")
                else:
                    curated_entries.append(entry)
                    project_stats_list.append(project_stat)
            else:
                curated_entries.append(entry)
                project_stats_list.append(project_stat)
        else:
            print(f"✗ {reason}")
    
    # Save curated dataset
    output_path = Path(args.output)
    with open(output_path, "w") as f:
        json.dump(curated_entries, f, indent=2)
    
    console.print(f"\n[green]✓ Curated dataset saved to {output_path}[/green]")
    console.print(f"[green]  Selected {len(curated_entries)} out of {len(dataset)} projects[/green]")
    
    # Generate report
    report_path = Path(args.report)
    generate_report(project_stats_list, len(dataset), report_path, args.min_vulnerabilities, args.min_high_critical)
    
    console.print(f"[green]✓ Report saved to {report_path}[/green]")
    
    # Display summary table
    print("\n" + "="*60)
    print("CURATED PROJECTS SUMMARY")
    print("="*60)
    print(f"{'Project':<30} {'Vulns':<10} {'Crit/High':<10} {'Sol Lines':<10}")
    print("-"*60)
    
    for stats in project_stats_list[:10]:  # Show first 10
        sol_lines = stats.cloc_stats.get("solidity_lines", "N/A")
        if sol_lines != "N/A":
            sol_lines = f"{sol_lines:,}"
        
        print(f"{stats.project_name[:30]:<30} {stats.total_vulnerabilities:<10} "
              f"{stats.critical_count + stats.high_count:<10} {str(sol_lines):<10}")
    
    if len(project_stats_list) > 10:
        print(f"\n... and {len(project_stats_list) - 10} more projects")


if __name__ == "__main__":
    main()
