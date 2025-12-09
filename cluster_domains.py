"""
# Cluster by nameServers and registrant_organization
python cluster_domains.py domains.txt output.txt -f nameServers registrant_organization

# Cluster by multiple fields with minimum 5 domains per cluster
python cluster_domains.py domains.txt output.txt -f nameServers registrant_organization ip_asn -m 5

# Cluster by registrar and IP details
python cluster_domains.py domains.txt output.txt -f registrarName ip_org ip_country
"""
import csv
from collections import defaultdict
from typing import List, Set
import argparse

class DomainClusterer:
    """Efficiently cluster domains based on shared attributes."""

    # Field definitions from your format
    FIELD_NAMES = [
        'domain', 'registrarName', 'registrarIANAID', 'createdDate', 'updatedDate',
        'expiresDate', 'abuseEmail', 'nameServers', 'status', 'registrant_name',
        'registrant_organization', 'registrant_street1', 'registrant_city',
        'registrant_state', 'registrant_postalCode', 'registrant_country',
        'registrant_telephone', 'registrant_fax', 'registrant_email',
        'admin_name', 'admin_organization', 'admin_street1', 'admin_city',
        'admin_state', 'admin_postalCode', 'admin_country', 'admin_telephone',
        'admin_fax', 'admin_email', 'tech_name', 'tech_organization',
        'tech_street1', 'tech_city', 'tech_state', 'tech_postalCode',
        'tech_country', 'tech_telephone', 'tech_fax', 'tech_email',
        'A_count', 'A_values', 'AAAA_count', 'AAAA_values', 'MX_count',
        'MX_values', 'NS_count', 'NS_values', 'TXT_count', 'TXT_values',
        'SOA_value', 'DMARC_present', 'DMARC_value', 'ip_asn', 'ip_org',
        'ip_country', 'ip_region', 'ip_city', 'ip_latitude', 'ip_longitude'
    ]

    def __init__(self, cluster_fields: List[str]):
        """
        Initialize clusterer with fields to use for clustering.

        Args:
            cluster_fields: List of field names to use for clustering
        """
        self.cluster_fields = cluster_fields
        self.clusters = defaultdict(set)

    def _create_key(self, row: dict) -> str:
        """Create a unique key from specified fields."""
        key_parts = []
        for field in self.cluster_fields:
            value = row.get(field, '').strip()
            key_parts.append(value)
        return '|||'.join(key_parts)

    def process_file(self, input_file: str, batch_size: int = 10000) -> dict:
        """
        Process the input file and create clusters.

        Args:
            input_file: Path to input CSV/TXT file
            batch_size: Number of rows to process at once

        Returns:
            Dictionary mapping cluster keys to sets of domains
        """
        print(f"Processing file: {input_file}")
        print(f"Clustering on fields: {', '.join(self.cluster_fields)}")

        processed = 0

        with open(input_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f, fieldnames=self.FIELD_NAMES)

            for row in reader:
                domain = row.get('domain', '').strip()
                if not domain:
                    continue

                cluster_key = self._create_key(row)
                self.clusters[cluster_key].add(domain)

                processed += 1
                if processed % batch_size == 0:
                    print(f"Processed {processed:,} domains...")

        print(f"Total domains processed: {processed:,}")
        print(f"Total clusters found: {len(self.clusters):,}")

        return self.clusters

    def filter_clusters(self, min_size: int = 2) -> dict:
        """
        Filter clusters to only include those with minimum size.

        Args:
            min_size: Minimum number of domains in a cluster

        Returns:
            Filtered dictionary of clusters
        """
        filtered = {k: v for k, v in self.clusters.items() if len(v) >= min_size}
        print(f"Clusters with {min_size}+ domains: {len(filtered):,}")
        return filtered

    def save_results(self, output_file: str, min_size: int = 2):
        """
        Save clustering results to a file.

        Args:
            output_file: Path to output file
            min_size: Minimum cluster size to include
        """
        filtered = self.filter_clusters(min_size)

        # Sort clusters by size (largest first)
        sorted_clusters = sorted(filtered.items(), key=lambda x: len(x[1]), reverse=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write(f"DOMAIN CLUSTERING RESULTS\n")
            f.write(f"Clustered by: {', '.join(self.cluster_fields)}\n")
            f.write(f"Total clusters: {len(sorted_clusters):,}\n")
            f.write("=" * 80 + "\n\n")

            for i, (key, domains) in enumerate(sorted_clusters, 1):
                f.write(f"\n{'='*80}\n")
                f.write(f"CLUSTER #{i} - {len(domains)} domains\n")
                f.write(f"{'='*80}\n")

                # Parse and display key values
                key_parts = key.split('|||')
                for field, value in zip(self.cluster_fields, key_parts):
                    if value:
                        f.write(f"  {field}: {value}\n")

                f.write(f"\nDomains in this cluster:\n")
                for domain in sorted(domains):
                    f.write(f"  - {domain}\n")

        print(f"\nResults saved to: {output_file}")

    def get_statistics(self) -> dict:
        """Get clustering statistics."""
        sizes = [len(domains) for domains in self.clusters.values()]

        return {
            'total_clusters': len(self.clusters),
            'total_domains': sum(sizes),
            'largest_cluster': max(sizes) if sizes else 0,
            'smallest_cluster': min(sizes) if sizes else 0,
            'avg_cluster_size': sum(sizes) / len(sizes) if sizes else 0
        }


def main():
    parser = argparse.ArgumentParser(
        description='Cluster domains based on shared attributes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Cluster by nameServers and registrant_organization
  python script.py input.txt output.txt -f nameServers registrant_organization

  # Cluster by multiple fields with minimum cluster size of 5
  python script.py input.txt output.txt -f nameServers registrant_organization ip_asn -m 5

  # Cluster by registrar and IP organization
  python script.py input.txt output.txt -f registrarName ip_org
        """
    )

    parser.add_argument('input_file', help='Input CSV/TXT file with domain data')
    parser.add_argument('output_file', help='Output file for clustering results')
    parser.add_argument('-f', '--fields', nargs='+', required=True,
                       help='Fields to use for clustering (e.g., nameServers registrant_organization)')
    parser.add_argument('-m', '--min-size', type=int, default=2,
                       help='Minimum cluster size to include in output (default: 2)')

    args = parser.parse_args()

    # Create clusterer
    clusterer = DomainClusterer(args.fields)

    # Process file
    clusterer.process_file(args.input_file)

    # Display statistics
    stats = clusterer.get_statistics()
    print(f"\n{'='*60}")
    print("CLUSTERING STATISTICS")
    print(f"{'='*60}")
    print(f"Total clusters: {stats['total_clusters']:,}")
    print(f"Total domains: {stats['total_domains']:,}")
    print(f"Largest cluster: {stats['largest_cluster']:,} domains")
    print(f"Smallest cluster: {stats['smallest_cluster']:,} domains")
    print(f"Average cluster size: {stats['avg_cluster_size']:.2f} domains")

    # Save results
    clusterer.save_results(args.output_file, args.min_size)


if __name__ == '__main__':
    main()
