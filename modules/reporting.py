"""
Reporting Engine
"""

import json
import os
from datetime import datetime
from typing import Dict, Any

class ReportGenerator:
    def __init__(self, output_dir: str = './reaper_output'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate(self, results: Dict[str, Any]) -> str:
        """Generate comprehensive report"""
        # Create filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_safe = results['metadata']['target'].replace('.', '_')
        filename = f"reaperad_report_{target_safe}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)
        
        # Add generation metadata
        results['report'] = {
            'generated_at': datetime.now().isoformat(),
            'version': '4.0',
            'tool': 'Reaper-AD'
        }
        
        # Calculate statistics
        stats = {
            'total_credentials': len(results.get('credentials', [])),
            'total_escalation_paths': len(results.get('escalation', [])),
            'total_persistence_mechanisms': len(results.get('persistence', [])),
            'discovery_items': sum(len(v) for k, v in results.get('discovery', {}).items())
        }
        results['statistics'] = stats
        
        # Save to file
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=4, default=str)
        
        return filepath
