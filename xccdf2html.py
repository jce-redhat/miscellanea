#!/usr/bin/env python3
"""
XCCDF to HTML Converter
Parses DISA XCCDF files (STIGs and SRGs) and generates a static HTML viewer
Auto-detects document type and adjusts styling accordingly
Supports both ZIP files and direct XCCDF XML files
"""

import xml.etree.ElementTree as ET
import html
import sys
import zipfile
import io
import argparse
from pathlib import Path

# XML namespaces used in XCCDF files
NAMESPACES = {
    "xccdf": "http://checklists.nist.gov/xccdf/1.1",
    "dc": "http://purl.org/dc/elements/1.1/",
}


def find_xccdf_in_zip(zip_path):
    """Find and extract XCCDF XML file from ZIP archive"""
    with zipfile.ZipFile(zip_path, "r") as zip_file:
        # Look for XCCDF XML files in the archive
        xccdf_files = [f for f in zip_file.namelist() if f.endswith("xccdf.xml")]

        if not xccdf_files:
            raise ValueError(f"No XCCDF XML file found in {zip_path}")

        if len(xccdf_files) > 1:
            print(f"Found multiple XCCDF files, using: {xccdf_files[0]}")

        # Read the XCCDF file content into memory
        xccdf_content = zip_file.read(xccdf_files[0])
        return io.BytesIO(xccdf_content)


def detect_document_type(title, benchmark_id):
    """Detect if document is a STIG or SRG based on title and ID"""
    title_lower = title.lower()
    id_lower = benchmark_id.lower()

    if "stig" in title_lower or "stig" in id_lower:
        return "STIG"
    elif (
        "srg" in title_lower
        or "srg" in id_lower
        or "security requirements guide" in title_lower
    ):
        return "SRG"
    else:
        # Default to STIG if unclear
        return "XCCDF"


def parse_xccdf_xml(xml_source):
    """Parse XCCDF XML and extract all requirements

    Args:
        xml_source: Can be a file path (str/Path) or file-like object (BytesIO)
    """
    tree = ET.parse(xml_source)
    root = tree.getroot()

    # Extract document metadata
    benchmark_id = root.get("id", "")
    title = root.find(".//xccdf:title", NAMESPACES)
    description = root.find(".//xccdf:description", NAMESPACES)
    version = root.find(".//xccdf:version", NAMESPACES)
    release_info = root.find('.//xccdf:plain-text[@id="release-info"]', NAMESPACES)

    doc_info = {
        "benchmark_id": benchmark_id,
        "title": title.text if title is not None else "Security Guide",
        "description": description.text if description is not None else "",
        "version": version.text if version is not None else "",
        "release_info": release_info.text if release_info is not None else "",
        "doc_type": "XCCDF",  # Will be updated after detection
    }

    # Detect document type
    doc_info["doc_type"] = detect_document_type(doc_info["title"], benchmark_id)

    # Extract all requirements/rules
    requirements = []
    for group in root.findall(".//xccdf:Group", NAMESPACES):
        group_id = group.get("id", "")
        rule = group.find(".//xccdf:Rule", NAMESPACES)

        if rule is not None:
            rule_id = rule.get("id", "")
            severity = rule.get("severity", "medium")

            # Extract rule details
            version_elem = rule.find("xccdf:version", NAMESPACES)
            title_elem = rule.find("xccdf:title", NAMESPACES)
            description_elem = rule.find("xccdf:description", NAMESPACES)

            # Extract all structured fields from description
            vuln_discussion = ""
            false_positives = ""
            false_negatives = ""
            documentable = ""
            mitigations = ""
            severity_override = ""
            potential_impacts = ""
            third_party_tools = ""
            mitigation_control = ""
            responsibility = ""
            ia_controls = ""

            if description_elem is not None and description_elem.text:
                desc_text = description_elem.text

                # Extract all fields - check both plain XML and HTML-encoded formats
                for field_name, var_name in [
                    ("VulnDiscussion", "vuln_discussion"),
                    ("FalsePositives", "false_positives"),
                    ("FalseNegatives", "false_negatives"),
                    ("Documentable", "documentable"),
                    ("Mitigations", "mitigations"),
                    ("SeverityOverrideGuidance", "severity_override"),
                    ("PotentialImpacts", "potential_impacts"),
                    ("ThirdPartyTools", "third_party_tools"),
                    ("MitigationControl", "mitigation_control"),
                    ("Responsibility", "responsibility"),
                    ("IAControls", "ia_controls"),
                ]:
                    # Try plain XML format first
                    start_tag = f"<{field_name}>"
                    end_tag = f"</{field_name}>"
                    if start_tag in desc_text:
                        start = desc_text.find(start_tag) + len(start_tag)
                        end = desc_text.find(end_tag)
                        if end > start:
                            locals()[var_name] = desc_text[start:end].strip()
                    else:
                        # Try HTML-encoded format
                        start_tag = f"&lt;{field_name}&gt;"
                        end_tag = f"&lt;/{field_name}&gt;"
                        if start_tag in desc_text:
                            start = desc_text.find(start_tag) + len(start_tag)
                            end = desc_text.find(end_tag)
                            if end > start:
                                locals()[var_name] = desc_text[start:end].strip()

            # Extract check content
            check_elem = rule.find(".//xccdf:check-content", NAMESPACES)
            check_content = check_elem.text if check_elem is not None else ""

            # Extract fix text
            fixtext_elem = rule.find(".//xccdf:fixtext", NAMESPACES)
            fix_text = fixtext_elem.text if fixtext_elem is not None else ""

            # Extract CCI references
            cci_refs = []
            for ident in rule.findall(".//xccdf:ident", NAMESPACES):
                if ident.get("system") == "http://cyber.mil/cci":
                    cci_refs.append(ident.text)

            # Extract group title (often contains SRG reference)
            group_title = group.find("xccdf:title", NAMESPACES)

            requirements.append(
                {
                    "group_id": group_id,
                    "rule_id": rule_id,
                    "version": version_elem.text if version_elem is not None else "",
                    "severity": severity,
                    "title": title_elem.text if title_elem is not None else "",
                    "discussion": vuln_discussion,
                    "check": check_content,
                    "fix": fix_text,
                    "cci": cci_refs,
                    "group_title": group_title.text if group_title is not None else "",
                    "false_positives": false_positives,
                    "false_negatives": false_negatives,
                    "documentable": documentable,
                    "mitigations": mitigations,
                    "severity_override": severity_override,
                    "potential_impacts": potential_impacts,
                    "third_party_tools": third_party_tools,
                    "mitigation_control": mitigation_control,
                    "responsibility": responsibility,
                    "ia_controls": ia_controls,
                }
            )

    return doc_info, requirements


def get_theme_colors(doc_type):
    """Return color scheme based on document type"""
    themes = {
        "STIG": {
            "gradient_start": "#1e3a8a",  # Blue
            "gradient_end": "#3b82f6",
            "focus_color": "#3b82f6",
            "cci_bg": "#eff6ff",
            "cci_text": "#1e40af",
        },
        "SRG": {
            "gradient_start": "#059669",  # Green
            "gradient_end": "#10b981",
            "focus_color": "#10b981",
            "cci_bg": "#ecfdf5",
            "cci_text": "#065f46",
        },
        "XCCDF": {
            "gradient_start": "#7c3aed",  # Purple
            "gradient_end": "#a78bfa",
            "focus_color": "#8b5cf6",
            "cci_bg": "#f5f3ff",
            "cci_text": "#5b21b6",
        },
    }
    return themes.get(doc_type, themes["XCCDF"])


def get_base_colors(mode):
    """Return base color scheme for light or dark mode"""
    if mode == "dark":
        return {
            "bg_primary": "#1a1a1a",
            "bg_secondary": "#2d2d2d",
            "bg_tertiary": "#3a3a3a",
            "bg_card": "#252525",
            "bg_card_hover": "#2d2d2d",
            "bg_input": "#2d2d2d",
            "text_primary": "#e5e5e5",
            "text_secondary": "#b8b8b8",
            "text_muted": "#808080",
            "border_color": "#404040",
            "border_light": "#4a4a4a",
        }
    else:  # light mode
        return {
            "bg_primary": "#f5f5f5",
            "bg_secondary": "#fafafa",
            "bg_tertiary": "#f3f4f6",
            "bg_card": "white",
            "bg_card_hover": "#f3f4f6",
            "bg_input": "white",
            "text_primary": "#1f2937",
            "text_secondary": "#374151",
            "text_muted": "#6b7280",
            "border_color": "#e5e7eb",
            "border_light": "#f3f4f6",
        }


def generate_html(doc_info, requirements, output_file, mode="light"):
    """Generate static HTML page"""

    theme = get_theme_colors(doc_info["doc_type"])
    base = get_base_colors(mode)

    # Determine subtitle based on doc type
    subtitle = ""
    if doc_info["doc_type"] == "STIG":
        subtitle = "Security Technical Implementation Guide"
    elif doc_info["doc_type"] == "SRG":
        subtitle = "Security Requirements Guide"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(doc_info['title'])}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: {base['text_primary']};
            background: {base['bg_primary']};
        }}

        .header {{
            background: linear-gradient(135deg, {theme['gradient_start']} 0%, {theme['gradient_end']} 100%);
            color: white;
            padding: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .header h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}

        .header .subtitle {{
            font-size: 1.1rem;
            opacity: 0.95;
            margin-bottom: 0.5rem;
        }}

        .header .meta {{
            opacity: 0.9;
            font-size: 0.9rem;
        }}

        .header .doc-type-badge {{
            display: inline-block;
            background: rgba(255, 255, 255, 0.2);
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
            margin-top: 0.5rem;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}

        .search-box {{
            background: {base['bg_card']};
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}

        .search-box input {{
            width: 100%;
            padding: 0.75rem;
            border: 2px solid {base['border_color']};
            border-radius: 6px;
            font-size: 1rem;
            transition: border-color 0.2s;
            background: {base['bg_input']};
            color: {base['text_primary']};
        }}

        .search-box input:focus {{
            outline: none;
            border-color: {theme['focus_color']};
        }}

        .filter-badges {{
            display: flex;
            gap: 0.5rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }}

        .badge {{
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s;
            border: 2px solid transparent;
        }}

        .badge.high {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .badge.medium {{
            background: #fef3c7;
            color: #92400e;
        }}

        .badge.low {{
            background: #dbeafe;
            color: #1e40af;
        }}

        .badge.active {{
            border-color: currentColor;
            font-weight: 600;
        }}

        .stats {{
            background: {base['bg_card']};
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 2rem;
            display: flex;
            gap: 2rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            flex-wrap: wrap;
        }}

        .stat {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .stat-label {{
            color: {base['text_muted']};
            font-size: 0.9rem;
        }}

        .stat-value {{
            font-weight: 600;
            font-size: 1.1rem;
            color: {base['text_primary']};
        }}

        .requirement-card {{
            background: {base['bg_card']};
            border-radius: 8px;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}

        .requirement-card:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}

        .requirement-header {{
            padding: 1.5rem;
            cursor: pointer;
            display: flex;
            align-items: flex-start;
            gap: 1rem;
            background: {base['bg_secondary']};
            border-bottom: 1px solid {base['border_color']};
        }}

        .requirement-header:hover {{
            background: {base['bg_card_hover']};
        }}

        .severity-badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
        }}

        .severity-high {{
            background: #dc2626;
            color: white;
        }}

        .severity-medium {{
            background: #f59e0b;
            color: white;
        }}

        .severity-low {{
            background: #3b82f6;
            color: white;
        }}

        .requirement-title-section {{
            flex: 1;
        }}

        .requirement-ids {{
            display: flex;
            gap: 1rem;
            margin-bottom: 0.5rem;
            flex-wrap: wrap;
        }}

        .requirement-id {{
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            color: {base['text_secondary']};
            background: {base['bg_tertiary']};
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-weight: 500;
        }}

        .requirement-title {{
            font-size: 1.1rem;
            font-weight: 600;
            color: {base['text_primary']};
            margin-bottom: 0.5rem;
        }}

        .requirement-group-title {{
            color: {base['text_muted']};
            font-size: 0.85rem;
        }}

        .expand-icon {{
            color: {base['text_secondary']};
            font-size: 1.5rem;
            transition: transform 0.2s;
            user-select: none;
        }}

        .requirement-card.expanded .expand-icon {{
            transform: rotate(180deg);
        }}

        .requirement-body {{
            display: none;
            padding: 0;
        }}

        .requirement-card.expanded .requirement-body {{
            display: block;
        }}

        .requirement-section {{
            padding: 1.5rem;
            border-bottom: 1px solid {base['border_color']};
        }}

        .requirement-section:last-child {{
            border-bottom: none;
        }}

        .requirement-section h3 {{
            font-size: 0.95rem;
            font-weight: 600;
            color: {base['text_secondary']};
            margin-bottom: 1rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .requirement-section-content {{
            color: {base['text_secondary']};
            white-space: pre-wrap;
            font-size: 0.95rem;
            line-height: 1.7;
        }}

        .cci-list {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}

        .cci-tag {{
            background: {theme['cci_bg']};
            color: {theme['cci_text']};
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.85rem;
            font-family: 'Courier New', monospace;
        }}

        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1rem;
        }}

        .meta-item {{
            background: {base['bg_tertiary']};
            padding: 1rem;
            border-radius: 6px;
        }}

        .meta-item h4 {{
            font-size: 0.85rem;
            font-weight: 600;
            color: {base['text_muted']};
            margin-bottom: 0.5rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .meta-item p {{
            color: {base['text_secondary']};
            font-size: 0.9rem;
        }}

        .no-results {{
            text-align: center;
            padding: 3rem;
            color: {base['text_muted']};
        }}

        .footer {{
            text-align: center;
            padding: 2rem;
            color: {base['text_muted']};
            font-size: 0.9rem;
        }}

        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}

            .header {{
                padding: 1rem;
            }}

            .header h1 {{
                font-size: 1.5rem;
            }}

            .stats {{
                flex-direction: column;
                gap: 1rem;
            }}

            .meta-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{html.escape(doc_info['title'])}</h1>"""

    if subtitle:
        html_content += f"""
        <div class="subtitle">{subtitle}</div>"""

    html_content += f"""
        <div class="meta">
            {html.escape(doc_info['release_info'])} | Version {html.escape(doc_info['version'])}
        </div>
        <div class="doc-type-badge">{doc_info['doc_type']} Document</div>
    </div>

    <div class="container">
        <div class="search-box">
            <input type="text" id="searchInput" placeholder="Search requirements by ID, title, or description...">
            <div class="filter-badges">
                <span class="badge high" data-severity="high">High Severity</span>
                <span class="badge medium" data-severity="medium">Medium Severity</span>
                <span class="badge low" data-severity="low">Low Severity</span>
            </div>
        </div>

        <div class="stats">
            <div class="stat">
                <span class="stat-label">Total Requirements:</span>
                <span class="stat-value" id="totalCount">{len(requirements)}</span>
            </div>
            <div class="stat">
                <span class="stat-label">Visible:</span>
                <span class="stat-value" id="visibleCount">{len(requirements)}</span>
            </div>
        </div>

        <div id="requirementsContainer">
"""

    # Add each requirement
    for req in requirements:
        severity_class = f"severity-{req['severity']}"

        search_text = " ".join(
            [
                req["group_id"],
                req["version"],
                req["title"],
                req["discussion"],
                req["group_title"],
            ]
        ).lower()

        html_content += f"""
            <div class="requirement-card" data-severity="{html.escape(req['severity'])}" data-search-text="{html.escape(search_text)}">
                <div class="requirement-header">
                    <span class="severity-badge {severity_class}">{html.escape(req['severity'])}</span>
                    <div class="requirement-title-section">
                        <div class="requirement-ids">
                            <span class="requirement-id">{html.escape(req['group_id'])}</span>
                            <span class="requirement-id">{html.escape(req['version'])}</span>
                        </div>
                        <div class="requirement-title">{html.escape(req['title'])}</div>
                        <div class="requirement-group-title">{html.escape(req['group_title'])}</div>
                    </div>
                    <div class="expand-icon">▼</div>
                </div>
                <div class="requirement-body">"""

        # Add discussion if present
        if req["discussion"]:
            html_content += f"""
                    <div class="requirement-section">
                        <h3>Discussion</h3>
                        <div class="requirement-section-content">{html.escape(req['discussion'])}</div>
                    </div>"""

        # Add check content if present
        if req["check"]:
            html_content += f"""
                    <div class="requirement-section">
                        <h3>Check Content</h3>
                        <div class="requirement-section-content">{html.escape(req['check'])}</div>
                    </div>"""

        # Add fix text if present
        if req["fix"]:
            html_content += f"""
                    <div class="requirement-section">
                        <h3>Fix Text</h3>
                        <div class="requirement-section-content">{html.escape(req['fix'])}</div>
                    </div>"""

        # Add CCI references
        if req["cci"]:
            html_content += f"""
                    <div class="requirement-section">
                        <h3>CCI References</h3>
                        <div class="cci-list">"""
            for cci in req["cci"]:
                html_content += f'                            <span class="cci-tag">{html.escape(cci)}</span>\n'
            html_content += """                        </div>
                    </div>"""

        # Add additional metadata if present
        meta_items = []
        if req["responsibility"]:
            meta_items.append(("Responsibility", req["responsibility"]))
        if req["ia_controls"]:
            meta_items.append(("IA Controls", req["ia_controls"]))
        if req["severity_override"]:
            meta_items.append(("Severity Override Guidance", req["severity_override"]))
        if req["potential_impacts"]:
            meta_items.append(("Potential Impacts", req["potential_impacts"]))
        if req["mitigations"]:
            meta_items.append(("Mitigations", req["mitigations"]))
        if req["documentable"]:
            meta_items.append(("Documentable", req["documentable"]))
        if req["false_positives"]:
            meta_items.append(("False Positives", req["false_positives"]))
        if req["false_negatives"]:
            meta_items.append(("False Negatives", req["false_negatives"]))
        if req["third_party_tools"]:
            meta_items.append(("Third Party Tools", req["third_party_tools"]))
        if req["mitigation_control"]:
            meta_items.append(("Mitigation Control", req["mitigation_control"]))

        if meta_items:
            html_content += """
                    <div class="requirement-section">
                        <h3>Additional Information</h3>
                        <div class="meta-grid">"""
            for label, value in meta_items:
                html_content += f"""
                            <div class="meta-item">
                                <h4>{html.escape(label)}</h4>
                                <p>{html.escape(value)}</p>
                            </div>"""
            html_content += """                        </div>
                    </div>"""

        html_content += """                </div>
            </div>
"""

    html_content += """
        </div>

        <div class="no-results" id="noResults" style="display: none;">
            <h2>No requirements found</h2>
            <p>Try adjusting your search or filters</p>
        </div>
    </div>

    <div class="footer">
        Generated XCCDF Viewer | For local viewing only
    </div>

    <script>
        // Toggle requirement expansion
        document.querySelectorAll('.requirement-header').forEach(header => {
            header.addEventListener('click', () => {
                header.closest('.requirement-card').classList.toggle('expanded');
            });
        });

        // Search functionality
        const searchInput = document.getElementById('searchInput');
        const filterBadges = document.querySelectorAll('.filter-badges .badge');
        const requirementCards = document.querySelectorAll('.requirement-card');
        const visibleCount = document.getElementById('visibleCount');
        const noResults = document.getElementById('noResults');
        const requirementsContainer = document.getElementById('requirementsContainer');

        let activeSeverity = null;

        function filterRequirements() {
            const searchTerm = searchInput.value.toLowerCase();
            let visible = 0;

            requirementCards.forEach(card => {
                const searchText = card.getAttribute('data-search-text');
                const severity = card.getAttribute('data-severity');

                const matchesSearch = !searchTerm || searchText.includes(searchTerm);
                const matchesSeverity = !activeSeverity || severity === activeSeverity;

                if (matchesSearch && matchesSeverity) {
                    card.style.display = '';
                    visible++;
                } else {
                    card.style.display = 'none';
                }
            });

            visibleCount.textContent = visible;

            if (visible === 0) {
                requirementsContainer.style.display = 'none';
                noResults.style.display = 'block';
            } else {
                requirementsContainer.style.display = 'block';
                noResults.style.display = 'none';
            }
        }

        searchInput.addEventListener('input', filterRequirements);

        filterBadges.forEach(badge => {
            badge.addEventListener('click', () => {
                const severity = badge.getAttribute('data-severity');

                if (activeSeverity === severity) {
                    activeSeverity = null;
                    badge.classList.remove('active');
                } else {
                    filterBadges.forEach(b => b.classList.remove('active'));
                    activeSeverity = severity;
                    badge.classList.add('active');
                }

                filterRequirements();
            });
        });
    </script>
</body>
</html>
"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_content)


def main():
    parser = argparse.ArgumentParser(
        description="Convert XCCDF files (STIGs and SRGs) to HTML viewer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python xccdf2html.py U_RHEL_9_V2R8_STIG.zip
  python xccdf2html.py U_Web_Server_V4R4_SRG.zip output.html
  python xccdf2html.py /path/to/xccdf.xml --mode dark
  python xccdf2html.py U_RHEL_9_V2R8_STIG.zip custom.html --mode dark
""",
    )

    parser.add_argument("input_file", help="Path to XCCDF ZIP file or XML file")
    parser.add_argument(
        "output_file", nargs="?", help="Output HTML file (default: input_stem.html)"
    )
    parser.add_argument(
        "--mode",
        choices=["light", "dark"],
        default="light",
        help="Color theme for HTML output (default: light)",
    )

    args = parser.parse_args()

    input_path = Path(args.input_file)

    if not input_path.exists():
        print(f"Error: File {args.input_file} not found")
        sys.exit(1)

    # Generate default output filename based on input
    if args.output_file:
        output_file = args.output_file
    else:
        output_file = f"{input_path.stem}.html"

    # Check if input is a ZIP file
    if input_path.suffix.lower() == ".zip":
        print(f"Extracting XCCDF from {args.input_file}...")
        try:
            xml_source = find_xccdf_in_zip(args.input_file)
            print(f"Parsing XCCDF content...")
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        # Assume it's an XML file
        print(f"Parsing {args.input_file}...")
        xml_source = args.input_file

    doc_info, requirements = parse_xccdf_xml(xml_source)

    # Count by severity
    severity_counts = {"high": 0, "medium": 0, "low": 0}
    for req in requirements:
        severity_counts[req["severity"]] = severity_counts.get(req["severity"], 0) + 1

    print(f"\nDocument Type: {doc_info['doc_type']}")
    print(f"Title: {doc_info['title']}")
    print(f"Mode: {args.mode}")
    print(f"\nFound {len(requirements)} requirements:")
    print(f"  High:   {severity_counts.get('high', 0)}")
    print(f"  Medium: {severity_counts.get('medium', 0)}")
    print(f"  Low:    {severity_counts.get('low', 0)}")
    print(f"\nGenerating HTML viewer...")

    generate_html(doc_info, requirements, output_file, args.mode)

    print(f"✓ Generated: {output_file}")
    print(f"\nOpen in your browser:")
    print(f"  file://{Path(output_file).absolute()}")


if __name__ == "__main__":
    main()
