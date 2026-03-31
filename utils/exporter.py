"""Export module for saving reconnaissance results."""

import csv
import json
from dataclasses import asdict
from typing import Dict, List

from core.dataclasses import GeoIPData


class ExportModule:
    """Export reconnaissance results to JSON/CSV formats."""

    @staticmethod
    def export_json(results: Dict, filepath: str) -> bool:
        """Export results to JSON file."""
        try:
            # Convert dataclass objects to dicts
            export_data = {}
            for key, value in results.items():
                if value is None:
                    export_data[key] = None
                elif isinstance(value, dict):
                    # Handle DNS results dict
                    export_data[key] = {}
                    for k, v in value.items():
                        if hasattr(v, '__dataclass_fields__'):
                            export_data[key][k] = asdict(v)
                        else:
                            export_data[key][k] = v
                elif isinstance(value, list):
                    export_data[key] = [
                        asdict(v) if hasattr(v, '__dataclass_fields__') else v
                        for v in value
                    ]
                elif hasattr(value, '__dataclass_fields__'):
                    export_data[key] = asdict(value)
                else:
                    export_data[key] = value
            
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            return True
        except Exception as e:
            return False

    @staticmethod
    def export_csv(results: Dict, filepath: str) -> bool:
        """Export results to CSV file."""
        try:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Flatten nested data for CSV
                writer.writerow(['Category', 'Key', 'Value'])
                
                for category, data in results.items():
                    if data is None:
                        writer.writerow([category, 'N/A', 'No data'])
                    elif isinstance(data, list):
                        for item in data:
                            if hasattr(item, '__dataclass_fields__'):
                                for key, value in asdict(item).items():
                                    writer.writerow([category, key, str(value)])
                            else:
                                writer.writerow([category, 'item', str(item)])
                    elif hasattr(data, '__dataclass_fields__'):
                        for key, value in asdict(data).items():
                            writer.writerow([category, key, str(value)])
                    else:
                        writer.writerow([category, 'value', str(data)])
            
            return True
        except Exception:
            return False

    @staticmethod
    def export_geojson(geoip_data: List[GeoIPData], filepath: str) -> bool:
        """Export GeoIP data to GeoJSON format."""
        try:
            features = []
            for data in geoip_data:
                feature = {
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [data.lon, data.lat]
                    },
                    "properties": {
                        "ip": data.ip,
                        "country": data.country,
                        "region": data.region,
                        "city": data.city
                    }
                }
                features.append(feature)
            
            geojson = {
                "type": "FeatureCollection",
                "features": features
            }
            
            with open(filepath, 'w') as f:
                json.dump(geojson, f, indent=2)
            return True
        except Exception:
            return False
