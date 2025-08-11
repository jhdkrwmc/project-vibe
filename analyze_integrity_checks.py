"""
analyze_integrity_checks.py - Analyze potential integrity check candidates
"""

import json
import os

def analyze_candidates(json_file):
    """Analyze the integrity check candidates from the JSON file"""
    print("\n=== Analyzing Integrity Check Candidates ===\n")
    
    # Load the JSON data
    with open(json_file, 'r') as f:
        candidates = json.load(f)
    
    # Filter for the most promising candidates
    interesting = []
    for candidate in candidates:
        # Look for functions with memory reads and conditional branches
        mem_read = any('movx' in inst['disasm'].lower() 
                      for inst in candidate['instructions'])
        
        has_cond_branch = any(inst['disasm'].startswith(('jnz', 'jz', 'jc', 'jnc')) 
                            for inst in candidate['instructions'])
        
        if mem_read and has_cond_branch:
            # Calculate the number of memory operations
            mem_ops = sum(1 for inst in candidate['instructions'] 
                         if 'movx' in inst['disasm'].lower())
            
            # Calculate the number of conditional branches
            cond_branches = sum(1 for inst in candidate['instructions'] 
                              if inst['disasm'].startswith(('jnz', 'jz', 'jc', 'jnc')))
            
            interesting.append({
                'ea': candidate['ea'],
                'name': candidate['name'],
                'mem_ops': mem_ops,
                'cond_branches': cond_branches,
                'instructions': candidate['instructions']
            })
    
    # Sort by number of memory operations (descending)
    interesting.sort(key=lambda x: x['mem_ops'], reverse=True)
    
    # Print summary
    print(f"Found {len(interesting)} interesting candidates (of {len(candidates)} total)")
    print("\nTop candidates:")
    for i, cand in enumerate(interesting[:10], 1):
        print(f"{i}. {cand['name']} @ {cand['ea']} "
              f"(mem_ops={cand['mem_ops']}, branches={cand['cond_branches']})")
    
    # Save detailed analysis
    output_file = os.path.join(os.path.dirname(json_file), "integrity_analysis.txt")
    with open(output_file, 'w') as f:
        f.write("=== Integrity Check Analysis ===\n\n")
        f.write(f"Total candidates analyzed: {len(candidates)}\n")
        f.write(f"Interesting candidates found: {len(interesting)}\n\n")
        
        for i, cand in enumerate(interesting, 1):
            f.write(f"\n--- Candidate {i}: {cand['name']} @ {cand['ea']} ---\n")
            f.write(f"Memory operations: {cand['mem_ops']}\n")
            f.write(f"Conditional branches: {cand['cond_branches']}\n\n")
            
            f.write("Disassembly:\n")
            for inst in cand['instructions']:
                # Handle both hex string and integer EAs
                ea = int(inst['ea'], 16) if isinstance(inst['ea'], str) else inst['ea']
                f.write(f"  {ea:04X}: {inst['disasm']}\n")
    
    print(f"\nDetailed analysis saved to: {output_file}")
    return interesting

if __name__ == "__main__":
    json_file = os.path.join(os.path.dirname(__file__), "integrity_checks.json")
    analyze_candidates(json_file)
