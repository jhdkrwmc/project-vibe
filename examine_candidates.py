"""
examine_candidates.py - Examine top integrity check candidates in detail
"""

def analyze_candidate(candidate):
    """Analyze a single candidate in detail"""
    print(f"\n=== Analyzing Candidate: {candidate['name']} @ {candidate['ea']} ===")
    print(f"Memory operations: {candidate['mem_ops']}")
    print(f"Conditional branches: {candidate['cond_branches']}")
    
    # Print disassembly
    print("\nDisassembly:")
    for inst in candidate['instructions']:
        ea = int(inst['ea'], 16) if isinstance(inst['ea'], str) else inst['ea']
        print(f"  {ea:04X}: {inst['disasm']}")
    
    # Look for patterns
    has_memory_compare = any('cjne' in inst['disasm'].lower() for inst in candidate['instructions'])
    has_conditional_branch = any(inst['disasm'].startswith(('jnz', 'jz', 'jc', 'jnc')) 
                               for inst in candidate['instructions'])
    has_memory_read = any('movx' in inst['disasm'].lower() for inst in candidate['instructions'])
    
    print("\nAnalysis:")
    if has_memory_compare:
        print("- Contains memory comparison (CJNE)")
    if has_conditional_branch:
        print("- Contains conditional branches")
    if has_memory_read:
        print("- Reads from external memory")
    
    # Check if this looks like an integrity check
    if (has_memory_compare or has_conditional_branch) and has_memory_read:
        print("\nThis appears to be a potential integrity check:")
        print("1. Reads from memory (possibly firmware)")
        print("2. Performs comparison or conditional branch")
        print("3. May branch to different code paths based on the check")
    
    print("\n" + "="*60)

def main():
    # Load the candidates from the JSON file
    import json
    
    json_file = "integrity_checks.json"
    with open(json_file, 'r') as f:
        candidates = json.load(f)
    
    # Filter and sort candidates
    interesting = []
    for candidate in candidates:
        mem_ops = sum(1 for inst in candidate['instructions'] 
                     if 'movx' in inst['disasm'].lower())
        cond_branches = sum(1 for inst in candidate['instructions'] 
                          if inst['disasm'].startswith(('jnz', 'jz', 'jc', 'jnc')))
        
        if mem_ops > 0 and cond_branches > 0:
            interesting.append({
                'ea': candidate['ea'],
                'name': candidate['name'],
                'mem_ops': mem_ops,
                'cond_branches': cond_branches,
                'instructions': candidate['instructions']
            })
    
    # Sort by number of memory operations (descending)
    interesting.sort(key=lambda x: x['mem_ops'], reverse=True)
    
    # Analyze top 10 candidates
    for i, candidate in enumerate(interesting[:10], 1):
        print(f"\n\n{'='*60}")
        print(f"CANDIDATE {i} OF {min(10, len(interesting))}")
        analyze_candidate(candidate)

if __name__ == "__main__":
    main()
