#!/usr/bin/env python3
"""
010_config_diff.py - Network Configuration Diff Utility

Compare two network configuration files and highlight changes.
Supports hierarchical configs (Juniper, Cisco), flat configs, and YAML/JSON.

Real-world use case: Verify what changed during provisioning, compliance checks,
change audits, and configuration drift detection.
"""

import sys
import json
from pathlib import Path
from difflib import unified_diff, SequenceMatcher
from typing import Dict, List


class ConfigDiffer:
    """Compare network configs and highlight changes."""
    
    def __init__(self, before_file: str, after_file: str, context_lines: int = 3):
        """
        Initialize differ with two config files.
        
        Args:
            before_file: Path to original config
            after_file: Path to modified config
            context_lines: Lines of context around changes (unified diff)
        """
        self.before = Path(before_file).read_text().splitlines(keepends=False)
        self.after = Path(after_file).read_text().splitlines(keepends=False)
        self.context = context_lines
    
    def get_unified_diff(self) -> str:
        """Return unified diff (git-style)."""
        diff = unified_diff(
            self.before, 
            self.after, 
            fromfile="before", 
            tofile="after",
            lineterm="",
            n=self.context
        )
        return "\n".join(diff)
    
    def get_side_by_side(self) -> str:
        """Return side-by-side comparison for small configs."""
        output = []
        max_width = 60
        output.append(f"{'BEFORE':<{max_width}} | {'AFTER':<{max_width}}")
        output.append("-" * (max_width * 2 + 3))
        
        max_lines = max(len(self.before), len(self.after))
        for i in range(max_lines):
            before_line = self.before[i][:max_width] if i < len(self.before) else ""
            after_line = self.after[i][:max_width] if i < len(self.after) else ""
            
            marker = " "
            if before_line != after_line:
                marker = "*"
            
            output.append(f"{before_line:<{max_width}} {marker} {after_line:<{max_width}}")
        
        return "\n".join(output)
    
    def get_statistics(self) -> Dict[str, any]:
        """Return diff statistics."""
        matcher = SequenceMatcher(None, self.before, self.after)
        matching_blocks = matcher.get_matching_blocks()
        
        total_matching = sum(block.size for block in matching_blocks)
        
        return {
            "lines_before": len(self.before),
            "lines_after": len(self.after),
            "lines_unchanged": total_matching,
            "lines_added": len(self.after) - total_matching,
            "lines_removed": len(self.before) - total_matching,
            "similarity_ratio": f"{matcher.ratio():.1%}"
        }
    
    def get_section_changes(self) -> Dict[str, List[str]]:
        """Extract changes: added and removed lines (ignores comments/whitespace)."""
        changes = {"added": [], "removed": []}
        
        for line in self.after:
            if line not in self.before:
                if line.strip() and not line.strip().startswith("#"):
                    changes["added"].append(line)
        
        for line in self.before:
            if line not in self.after:
                if line.strip() and not line.strip().startswith("#"):
                    changes["removed"].append(line)
        
        return changes
    
    def colorize_diff(self) -> str:
        """Return unified diff with ANSI color codes."""
        diff = self.get_unified_diff()
        colored = []
        
        for line in diff.split("\n"):
            if line.startswith("+") and not line.startswith("+++"):
                colored.append(f"\033[92m{line}\033[0m")  # Green
            elif line.startswith("-") and not line.startswith("---"):
                colored.append(f"\033[91m{line}\033[0m")  # Red
            elif line.startswith("@"):
                colored.append(f"\033[94m{line}\033[0m")  # Blue
            else:
                colored.append(line)
        
        return "\n".join(colored)


def main():
    """CLI interface for config diff."""
    if len(sys.argv) < 3:
        print("Usage: 010_config_diff.py <before> <after> [--unified|--side-by-side|--stats|--changes|--color]")
        print("\nOptions:")
        print("  --unified        Unified diff format (default)")
        print("  --side-by-side   Side-by-side comparison")
        print("  --stats          Statistics only")
        print("  --changes        Added/removed lines only")
        print("  --color          Colored unified diff")
        sys.exit(1)
    
    before, after = sys.argv[1], sys.argv[2]
    output_format = sys.argv[3] if len(sys.argv) > 3 else "--unified"
    
    try:
        differ = ConfigDiffer(before, after)
        
        if output_format == "--side-by-side":
            print(differ.get_side_by_side())
        elif output_format == "--stats":
            stats = differ.get_statistics()
            print("\n=== Configuration Diff Statistics ===")
            for key, value in stats.items():
                print(f"{key:20s}: {value}")
        elif output_format == "--changes":
            changes = differ.get_section_changes()
            if changes["added"]:
                print("\n[+] ADDED:")
                for line in changes["added"]:
                    print(f"  + {line}")
            if changes["removed"]:
                print("\n[-] REMOVED:")
                for line in changes["removed"]:
                    print(f"  - {line}")
        elif output_format == "--color":
            print(differ.colorize_diff())
        else:
            diff_output = differ.get_unified_diff()
            print(diff_output if diff_output else "No differences found.")
    
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()