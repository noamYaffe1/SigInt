"""Probe points management utilities for additive scoring."""
from typing import Dict
from core.models import ProbePlan


def parse_weights_string(weights_str: str) -> Dict[str, int]:
    """Parse a points string into a dictionary.
    
    Supports two formats:
    1. By type: "favicon:80,image:50,title:15,body:15"
    2. By order: "1:100,2:50,3:30"
    
    Args:
        weights_str: Comma-separated key:value pairs
        
    Returns:
        Dictionary mapping probe type/order to points
    """
    weights = {}
    for part in weights_str.split(","):
        part = part.strip()
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key = key.strip().lower()
        try:
            weights[key] = int(value.strip())
        except ValueError:
            continue
    return weights


def apply_weights_to_plan(plan: ProbePlan, weights: Dict[str, int]) -> None:
    """Apply custom points to a probe plan.
    
    Args:
        plan: The probe plan to modify
        weights: Dictionary of points, can be:
            - By type: {"favicon": 80, "image": 50, "title": 15, "body": 15}
            - By order: {"1": 80, "2": 50, "3": 15, "4": 15}
    """
    # Type name mapping (shorthand -> full type name)
    type_map = {
        "favicon": "favicon_hash",
        "favicon_hash": "favicon_hash",
        "image": "image_hash",
        "image_hash": "image_hash",
        "page": "page_signature",
        "page_signature": "page_signature",
    }
    
    for key, weight in weights.items():
        # Check if it's an order number
        if key.isdigit():
            plan.set_weight_by_order(int(key), weight)
        # Check if it's a type name
        elif key in type_map:
            plan.set_probe_weight(type_map[key], weight)


def print_probe_weights(plan: ProbePlan) -> None:
    """Print current probe points in a formatted table.
    
    Args:
        plan: The probe plan to display
    """
    print("\n" + "=" * 70)
    print("PROBE POINTS (Additive Scoring)")
    print("=" * 70)
    print(f"{'#':>3}  {'Type':<18}  {'Path':<30}  {'Points':>6}")
    print("-" * 70)
    
    total_points = 0
    for step in plan.probe_steps:
        total_points += step.weight
        print(f"{step.order:>3}  {step.check_type:<18}  {step.url_path:<30}  {step.weight:>6}")
    
    print("-" * 70)
    print(f"{'Max possible score':<55}  {total_points:>6}")
    print(f"{'Verified threshold':<55}  {'80':>6}")
    print(f"{'Max score cap':<55}  {'100':>6}")
    print("=" * 70)
    print("Score = sum of matched probe points (capped at 100)")
    print("Early termination: stops probing when score reaches 100")
    print("=" * 70)


def interactive_weight_editor(plan: ProbePlan) -> ProbePlan:
    """Interactively edit probe points.
    
    Args:
        plan: The probe plan to edit
        
    Returns:
        Modified probe plan
    """
    print("\n" + "=" * 70)
    print("INTERACTIVE PROBE POINTS EDITOR")
    print("=" * 70)
    print("Set points for each probe type. Points are ADDITIVE:")
    print("  - Score = sum of matched probe points (capped at 100)")
    print("  - If score reaches 100, remaining probes are SKIPPED")
    print("")
    print("Example: Set favicon=80, and a favicon match = instant verification!")
    print("")
    print("Commands:")
    print("  <order> <points>  - Set points for probe #<order>")
    print("  favicon <points>  - Set points for all favicon probes")
    print("  image <points>    - Set points for all image probes")
    print("  page <points>     - Set points for all page probes")
    print("  show              - Show current points")
    print("  done / q          - Finish editing")
    print("=" * 70)
    
    # Show current weights
    print_probe_weights(plan)
    
    while True:
        try:
            cmd = input("\nPoints command (or 'done'): ").strip().lower()
            
            if cmd in ("done", "q", "quit", "exit", ""):
                break
            
            if cmd == "show":
                print_probe_weights(plan)
                continue
            
            parts = cmd.split()
            if len(parts) != 2:
                print("  [!] Invalid format. Use: <probe_or_type> <points>")
                continue
            
            key, points_str = parts
            try:
                points = int(points_str)
                if points < 0:
                    print("  [!] Points must be non-negative")
                    continue
            except ValueError:
                print("  [!] Points must be a number")
                continue
            
            # Apply points
            if key.isdigit():
                order = int(key)
                found = False
                for step in plan.probe_steps:
                    if step.order == order:
                        old_points = step.weight
                        step.weight = points
                        print(f"  ✓ Probe #{order}: {old_points} → {points} points")
                        found = True
                        break
                if not found:
                    print(f"  [!] No probe with order #{order}")
            elif key in ("favicon", "favicon_hash"):
                plan.set_probe_weight("favicon_hash", points)
                print(f"  ✓ All favicon probes: → {points} points")
            elif key in ("image", "image_hash"):
                plan.set_probe_weight("image_hash", points)
                print(f"  ✓ All image probes: → {points} points")
            elif key in ("page", "page_signature"):
                plan.set_probe_weight("page_signature", points)
                print(f"  ✓ All page signature probes: → {points} points")
            else:
                print(f"  [!] Unknown probe type: {key}")
                
        except KeyboardInterrupt:
            print("\n  [!] Cancelled")
            break
        except EOFError:
            break
    
    # Show final points
    print("\n" + "-" * 70)
    print("Final points configuration:")
    print_probe_weights(plan)
    
    return plan
