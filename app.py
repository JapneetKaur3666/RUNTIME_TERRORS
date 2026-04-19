import streamlit as st
import networkx as nx
import plotly.graph_objects as go
import json
import pandas as pd
import requests
from collections import deque
from typing import Dict, Tuple, Optional

st.set_page_config(page_title="CVE Impact Visualizer", layout="wide", page_icon="🛡️")

# Custom CSS for modern dashboard look
st.markdown("""
<style>
    /* Global font size increase */
    html, body, [class*="css"] {
        font-size: 16px;
    }
    
    /* Main title styling */
    h1 {
        font-size: 2.5rem !important;
        font-weight: 700 !important;
        color: #1f2937 !important;
        margin-bottom: 0.5rem !important;
    }
    
    /* Subtitle styling */
    .subtitle {
        font-size: 1.1rem;
        color: #6b7280;
        margin-bottom: 2rem;
    }
    
    /* Section headers */
    h2 {
        font-size: 1.8rem !important;
        font-weight: 600 !important;
        color: #374151 !important;
        margin-top: 1.5rem !important;
    }
    
    h3 {
        font-size: 1.4rem !important;
        font-weight: 600 !important;
        color: #4b5563 !important;
    }
    
    /* Card styling */
    .stMetric {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    
    .stMetric label {
        font-size: 1.1rem !important;
        font-weight: 500 !important;
        color: #6b7280 !important;
    }
    
    .stMetric [data-testid="stMetricValue"] {
        font-size: 2rem !important;
        font-weight: 700 !important;
        color: #1f2937 !important;
    }
    
    /* Button styling */
    .stButton > button {
        font-size: 1.1rem !important;
        font-weight: 600 !important;
        padding: 0.75rem 1.5rem !important;
        border-radius: 8px !important;
        transition: all 0.3s ease !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    }
    
    /* Info boxes */
    .stAlert {
        font-size: 1.05rem !important;
        padding: 1rem 1.5rem !important;
        border-radius: 8px !important;
    }
    
    /* Sidebar styling */
    [data-testid="stSidebar"] {
        background: #f9fafb;
        padding: 2rem 1rem;
    }
    
    [data-testid="stSidebar"] h2 {
        font-size: 1.3rem !important;
        color: #1f2937 !important;
    }
    
    [data-testid="stSidebar"] h3 {
        font-size: 1.1rem !important;
        color: #374151 !important;
    }
    
    /* Input fields */
    .stTextInput > div > div > input {
        font-size: 1.05rem !important;
        padding: 0.75rem !important;
        border-radius: 8px !important;
    }
    
    .stSelectbox > div > div > select {
        font-size: 1.05rem !important;
        padding: 0.75rem !important;
        border-radius: 8px !important;
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    
    .stTabs [data-baseweb="tab"] {
        font-size: 1.1rem !important;
        font-weight: 600 !important;
        padding: 0.75rem 1.5rem !important;
        border-radius: 8px 8px 0 0 !important;
    }
    
    /* Table styling */
    .stDataFrame {
        font-size: 1.1rem !important;
    }
    
    .stDataFrame th {
        font-size: 1.15rem !important;
        font-weight: 600 !important;
        padding: 0.75rem !important;
    }
    
    .stDataFrame td {
        font-size: 1.05rem !important;
        padding: 0.65rem !important;
    }
    
    /* Success/Warning/Error boxes */
    .stSuccess, .stWarning, .stError, .stInfo {
        font-size: 1.1rem !important;
        line-height: 1.7 !important;
        padding: 1.25rem !important;
    }
    
    .stSuccess p, .stWarning p, .stError p, .stInfo p {
        font-size: 1.05rem !important;
    }
    
    /* Markdown text in tabs */
    .stMarkdown {
        font-size: 1.05rem !important;
    }
    
    .stMarkdown p {
        font-size: 1.05rem !important;
        line-height: 1.6 !important;
    }
    
    .stMarkdown li {
        font-size: 1.05rem !important;
        line-height: 1.6 !important;
        margin-bottom: 0.5rem !important;
    }
    
    /* Expander text */
    .streamlit-expanderHeader {
        font-size: 1.15rem !important;
        font-weight: 600 !important;
    }
    
    .streamlit-expanderContent {
        font-size: 1.05rem !important;
    }
    
    /* Code blocks */
    code {
        font-size: 0.95rem !important;
        padding: 0.2rem 0.4rem !important;
        border-radius: 4px !important;
    }
    
    pre {
        font-size: 0.95rem !important;
        padding: 1rem !important;
        border-radius: 8px !important;
    }
    
    /* Container spacing */
    .block-container {
        padding-top: 2rem !important;
        padding-bottom: 2rem !important;
    }
    
    /* AI Suggestion Cards */
    .suggestion-card {
        background: white;
        padding: 1rem;
        border-radius: 8px;
        border-left: 4px solid #3b82f6;
        margin-bottom: 0.75rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    
    /* Status badges */
    .status-badge {
        display: inline-block;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        font-weight: 600;
        font-size: 1rem;
    }
    
    .status-applied {
        background: #d1fae5;
        color: #065f46;
    }
    
    .status-rejected {
        background: #fee2e2;
        color: #991b1b;
    }
    
    .status-pending {
        background: #dbeafe;
        color: #1e40af;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'analysis_done' not in st.session_state:
    st.session_state.analysis_done = False
if 'last_cve' not in st.session_state:
    st.session_state.last_cve = None
if 'selected_cve' not in st.session_state:
    st.session_state.selected_cve = None
if 'selected_package' not in st.session_state:
    st.session_state.selected_package = None
if 'fix_applied' not in st.session_state:
    st.session_state.fix_applied = False
if 'fix_rejected' not in st.session_state:
    st.session_state.fix_rejected = False
if 'ai_suggestions' not in st.session_state:
    st.session_state.ai_suggestions = []

# Load mock data
@st.cache_data
def load_mock_cve():
    try:
        with open('mock_cve.json', 'r') as f:
            return json.load(f)
    except:
        return {}

@st.cache_data
def load_mock_graphs():
    try:
        with open('mock_graph.json', 'r') as f:
            return json.load(f)
    except:
        return {}

# AI Risk Advisor - Suggests vulnerabilities based on dependency graph
def suggest_vulnerabilities(graph_data: dict) -> list:
    """
    Analyzes dependency graph and suggests likely vulnerabilities.
    Returns list of suggestions with package, CVE, and reason.
    """
    suggestions = []
    
    if not graph_data or 'nodes' not in graph_data:
        return suggestions
    
    nodes = graph_data.get('nodes', {})
    
    # CVE database for suggestions (package -> CVE mapping)
    cve_database = {
        'log4j-core': {
            'cve': 'CVE-2021-44228',
            'severity': 'CRITICAL',
            'reason': 'Log4Shell - Remote code execution vulnerability'
        },
        'log4j-api': {
            'cve': 'CVE-2021-45046',
            'severity': 'CRITICAL',
            'reason': 'Incomplete fix for Log4Shell'
        },
        'struts2-core': {
            'cve': 'CVE-2017-5638',
            'severity': 'CRITICAL',
            'reason': 'Equifax breach - Remote code execution'
        },
        'spring-beans': {
            'cve': 'CVE-2022-22965',
            'severity': 'CRITICAL',
            'reason': 'Spring4Shell - RCE via class loader'
        },
        'lodash': {
            'cve': 'CVE-2020-8203',
            'severity': 'HIGH',
            'reason': 'Prototype pollution vulnerability'
        },
        'urllib3': {
            'cve': 'CVE-2021-23336',
            'severity': 'MEDIUM',
            'reason': 'Web cache poisoning vulnerability'
        },
        'requests': {
            'cve': 'CVE-2023-32681',
            'severity': 'MEDIUM',
            'reason': 'Proxy authentication leak'
        },
        'flask': {
            'cve': 'CVE-2023-30861',
            'severity': 'HIGH',
            'reason': 'Cookie parsing vulnerability'
        },
        'django': {
            'cve': 'CVE-2023-36053',
            'severity': 'HIGH',
            'reason': 'Potential ReDoS in email validation'
        },
        'jquery': {
            'cve': 'CVE-2019-11358',
            'severity': 'MEDIUM',
            'reason': 'Prototype pollution in jQuery'
        },
        'xml2js': {
            'cve': 'CVE-2023-0842',
            'severity': 'HIGH',
            'reason': 'Prototype pollution vulnerability'
        },
        'pip': {
            'cve': 'CVE-2022-42969',
            'severity': 'HIGH',
            'reason': 'Arbitrary file write vulnerability'
        }
    }
    
    # Priority scoring based on node type and package characteristics
    priority_packages = []
    
    for package_name, attrs in nodes.items():
        node_type = attrs.get('type', 'low')
        
        # Calculate priority score
        priority_score = 0
        
        # Type-based scoring
        if node_type == 'critical':
            priority_score += 10
        elif node_type == 'medium':
            priority_score += 5
        
        # Name-based scoring (security-sensitive packages)
        security_keywords = ['auth', 'crypto', 'security', 'ssl', 'tls', 'log', 'spring', 'struts']
        network_keywords = ['http', 'request', 'url', 'network', 'socket', 'web']
        
        package_lower = package_name.lower()
        for keyword in security_keywords:
            if keyword in package_lower:
                priority_score += 8
                break
        
        for keyword in network_keywords:
            if keyword in package_lower:
                priority_score += 5
                break
        
        # Check if package has known CVE
        if package_name in cve_database:
            priority_score += 15
            priority_packages.append({
                'package': package_name,
                'score': priority_score,
                'cve_info': cve_database[package_name]
            })
    
    # Sort by priority score and take top 3
    priority_packages.sort(key=lambda x: x['score'], reverse=True)
    
    for pkg in priority_packages[:3]:
        suggestions.append({
            'package': pkg['package'],
            'cve': pkg['cve_info']['cve'],
            'severity': pkg['cve_info']['severity'],
            'reason': pkg['cve_info']['reason'],
            'score': pkg['score']
        })
    
    return suggestions

# Fetch CVE data from multiple sources
def get_vulnerable_package(cve_id: str) -> Optional[Tuple[str, str, float, str]]:
    """
    Returns (package_name, severity, cvss_score, source) or None
    Tries multiple APIs in order: OSV.dev → NVD → Mock data
    """
    
    # Package name normalization mapping (OSV.dev name -> common name)
    package_name_mapping = {
        'org.apache.logging.log4j:log4j-core': 'log4j-core',
        'org.apache.logging.log4j:log4j-api': 'log4j-api',
        'org.apache.struts:struts2-core': 'struts2-core',
        'org.springframework:spring-beans': 'spring-beans',
        'org.springframework:spring-core': 'spring-core',
        'com.fasterxml.jackson.core:jackson-databind': 'jackson-databind',
    }
    
    # Method 1: Try mock data FIRST (most reliable for demo)
    mock_data = load_mock_cve()
    if cve_id in mock_data:
        cve = mock_data[cve_id]
        ecosystem = cve.get('ecosystem', 'Local DB')
        st.success(f"✅ Found in local database: {cve['package']} ({ecosystem})")
        return (cve['package'], cve['severity'], cve.get('cvss_score', 5.0), 'Local DB')
    
    # Method 2: Try OSV.dev API
    try:
        st.info(f"🔍 Querying OSV.dev API for {cve_id}...")
        
        # Query by CVE ID
        response = requests.get(
            f"https://api.osv.dev/v1/vulns/{cve_id}",
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract package information
            package_name = None
            ecosystem = None
            
            if data.get('affected'):
                for affected_item in data['affected']:
                    package_info = affected_item.get('package', {})
                    if package_info.get('name'):
                        package_name = package_info.get('name')
                        ecosystem = package_info.get('ecosystem', 'unknown')
                        break
            
            # If no package found in affected, try to extract from summary/details
            if not package_name:
                # Try to extract from details or summary
                details = data.get('details', '') + ' ' + data.get('summary', '')
                
                # Common package patterns with ecosystem mapping
                package_patterns = {
                    'log4j': ('log4j-core', 'Maven'),
                    'urllib3': ('urllib3', 'PyPI'),
                    'lodash': ('lodash', 'npm'),
                    'django': ('django', 'PyPI'),
                    'flask': ('flask', 'PyPI'),
                    'requests': ('requests', 'PyPI'),
                    'spring': ('spring-beans', 'Maven'),
                    'struts': ('struts2-core', 'Maven'),
                    'jackson': ('jackson-databind', 'Maven'),
                    'jquery': ('jquery', 'npm'),
                    'xml2js': ('xml2js', 'npm'),
                    'pip': ('pip', 'PyPI'),
                    'werkzeug': ('werkzeug', 'PyPI'),
                    'jinja2': ('jinja2', 'PyPI'),
                    'certifi': ('certifi', 'PyPI'),
                    'pandas': ('pandas', 'PyPI'),
                    'numpy': ('numpy', 'PyPI'),
                    'express': ('express', 'npm'),
                    'react': ('react', 'npm'),
                    'vue': ('vue', 'npm'),
                    'angular': ('angular', 'npm'),
                    'fastapi': ('fastapi', 'PyPI'),
                    'celery': ('celery', 'PyPI'),
                }
                
                details_lower = details.lower()
                for keyword, (pkg_name, eco) in package_patterns.items():
                    if keyword in details_lower:
                        package_name = pkg_name
                        ecosystem = eco
                        st.info(f"📦 Extracted package from description: {package_name} ({ecosystem})")
                        break
            
            if package_name:
                # Normalize package name for common variations
                if package_name in package_name_mapping:
                    original_name = package_name
                    package_name = package_name_mapping[package_name]
                    st.info(f"📦 Normalized package name: {original_name} → {package_name}")
                
                # Extract severity
                severity = 'MEDIUM'
                score = 5.0
                
                # Check severity array
                severity_info = data.get('severity', [])
                if severity_info:
                    for sev_item in severity_info:
                        severity_score = sev_item.get('score', '')
                        
                        # Parse CVSS vector string
                        if isinstance(severity_score, str) and 'CVSS:' in severity_score:
                            try:
                                import re
                                # Estimate from impact metrics
                                if '/C:H/I:H/A:H' in severity_score:
                                    score = 9.8
                                elif '/C:H/I:H/' in severity_score:
                                    score = 9.0
                                elif '/C:H/' in severity_score or '/I:H/' in severity_score or '/A:H' in severity_score:
                                    score = 7.5
                                elif '/C:L/I:L/A:L' in severity_score:
                                    score = 5.0
                                else:
                                    score = 6.0
                            except:
                                score = 5.0
                
                # Determine severity level from score
                if score >= 9.0:
                    severity = 'CRITICAL'
                elif score >= 7.0:
                    severity = 'HIGH'
                elif score >= 4.0:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                
                st.success(f"✅ Found in OSV.dev: {package_name} ({ecosystem or 'unknown'}) - Severity: {severity}, Score: {score}")
                return (package_name, severity, score, 'OSV.dev')
    except Exception as e:
        st.warning(f"⚠️ OSV.dev API error: {str(e)}")
    
    # Method 2: Try NVD API (National Vulnerability Database)
    try:
        st.info(f"🔍 Querying NVD API for {cve_id}...")
        
        response = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={'cveId': cve_id},
            timeout=10,
            headers={'User-Agent': 'CVE-Impact-Visualizer/1.0'}
        )
        
        if response.status_code == 200:
            data = response.json()
            
            if data.get('vulnerabilities'):
                vuln = data['vulnerabilities'][0]['cve']
                
                # Extract CVSS score
                metrics = vuln.get('metrics', {})
                cvss_data = metrics.get('cvssMetricV31', []) or metrics.get('cvssMetricV3', []) or metrics.get('cvssMetricV2', [])
                
                if cvss_data:
                    cvss = cvss_data[0].get('cvssData', {})
                    score = cvss.get('baseScore', 5.0)
                    severity = cvss.get('baseSeverity', 'MEDIUM')
                else:
                    score = 5.0
                    severity = 'MEDIUM'
                
                # Try to extract package name from description
                descriptions = vuln.get('descriptions', [])
                description = descriptions[0].get('value', '') if descriptions else ''
                
                # Common package name patterns
                package_name = 'unknown'
                for keyword in ['Apache', 'Log4j', 'Spring', 'Struts', 'lodash', 'urllib3', 'Django', 'Flask']:
                    if keyword.lower() in description.lower():
                        package_name = keyword.lower()
                        break
                
                st.success(f"✅ Found in NVD: {package_name} (CVSS: {score})")
                return (package_name, severity, score, 'NVD')
    except Exception as e:
        st.warning(f"⚠️ NVD API error: {str(e)}")
    
    # If all methods fail
    st.error(f"❌ {cve_id} not found in any database (Local DB, OSV.dev, or NVD)")
    return None

# Build NetworkX graph
def build_graph(graph_data: dict) -> nx.DiGraph:
    G = nx.DiGraph()
    nodes = graph_data.get('nodes', {})
    edges = graph_data.get('edges', {})
    
    for node, attrs in nodes.items():
        G.add_node(node, **attrs)
    
    for source, targets in edges.items():
        for target in targets:
            G.add_edge(source, target)
    
    return G

# BFS risk propagation
def propagate_risk(G: nx.DiGraph, vulnerable_node: str, severity: str) -> Dict[str, dict]:
    """Returns dict of {node: {depth, risk_score, risk_level}}"""
    if vulnerable_node not in G.nodes():
        return {}
    
    severity_weight = {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 1, 'LOW': 0}
    type_weight = {'critical': 2, 'medium': 1, 'low': 0}
    
    sev_w = severity_weight.get(severity, 1)
    
    risk_data = {}
    queue = deque([(vulnerable_node, 0)])
    visited = {vulnerable_node}
    
    while queue:
        node, depth = queue.popleft()
        
        # Calculate depth score
        if depth == 0:
            depth_score = 3
        elif depth == 1:
            depth_score = 2
        else:
            depth_score = 1
        
        # Get node type weight
        node_type = G.nodes[node].get('type', 'low')
        impact_weight = type_weight.get(node_type, 0)
        
        # Final risk score
        final_score = depth_score + impact_weight + sev_w
        
        # Risk level
        if final_score >= 6:
            risk_level = 'HIGH'
        elif final_score >= 4:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        risk_data[node] = {
            'depth': depth,
            'risk_score': final_score,
            'risk_level': risk_level,
            'type': node_type,
            'version': G.nodes[node].get('version', 'unknown')
        }
        
        # BFS to dependencies
        for neighbor in G.neighbors(node):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, depth + 1))
    
    return risk_data

# Visualization with hierarchical layout
def create_risk_graph(G: nx.DiGraph, risk_data: dict, vulnerable_node: str):
    """
    Creates a hierarchical dependency graph visualization.
    
    Layout explanation:
    - TOP: Vulnerable package (red)
    - MIDDLE: Direct dependencies (orange/yellow)
    - BOTTOM: Indirect dependencies (yellow)
    - SIDES: Unaffected packages (green)
    
    Vertical position = dependency depth from vulnerable package
    Horizontal position = spread for readability
    """
    
    # Create hierarchical layout based on depth
    pos = {}
    
    # Organize nodes by depth
    depth_groups = {}
    for node in G.nodes():
        if node in risk_data:
            depth = risk_data[node]['depth']
            if depth not in depth_groups:
                depth_groups[depth] = []
            depth_groups[depth].append(node)
        else:
            # Unaffected nodes go to the side
            if -1 not in depth_groups:
                depth_groups[-1] = []
            depth_groups[-1].append(node)
    
    # Position nodes hierarchically
    max_depth = max(d for d in depth_groups.keys() if d >= 0) if depth_groups else 0
    
    for depth, nodes in depth_groups.items():
        num_nodes = len(nodes)
        
        if depth == -1:  # Unaffected nodes - place on right side
            for i, node in enumerate(nodes):
                x = 3.0  # Far right
                y = (i - num_nodes / 2) * 0.8
                pos[node] = (x, y)
        else:
            # Affected nodes - hierarchical top to bottom
            y = (max_depth - depth) * 2.0  # Higher depth = higher on screen
            for i, node in enumerate(nodes):
                x = (i - num_nodes / 2) * 1.5  # Spread horizontally
                pos[node] = (x, y)
    
    # Edges
    edge_traces = []
    for edge in G.edges():
        if edge[0] in pos and edge[1] in pos:
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            
            # Color edges based on whether they connect to vulnerable path
            edge_color = '#FF6B6B' if (edge[0] in risk_data and edge[1] in risk_data) else '#888'
            edge_width = 2 if (edge[0] in risk_data and edge[1] in risk_data) else 1
            
            edge_traces.append(go.Scatter(
                x=[x0, x1, None], y=[y0, y1, None],
                mode='lines',
                line=dict(width=edge_width, color=edge_color),
                hoverinfo='none',
                showlegend=False
            ))
    
    # Nodes
    node_x, node_y, node_text, node_color, node_size, node_labels = [], [], [], [], [], []
    
    for node in G.nodes():
        if node not in pos:
            continue
            
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        node_labels.append(node)
        
        if node in risk_data:
            rd = risk_data[node]
            node_text.append(
                f"<b>{node}</b><br>"
                f"Version: {rd['version']}<br>"
                f"Depth: {rd['depth']} (hops from vulnerability)<br>"
                f"Risk: {rd['risk_level']}<br>"
                f"Score: {rd['risk_score']}"
            )
            
            # Color by risk
            if rd['risk_level'] == 'HIGH':
                node_color.append('#FF0000')  # Red
                node_size.append(40)
            elif rd['risk_level'] == 'MEDIUM':
                node_color.append('#FF8C00')  # Orange
                node_size.append(30)
            else:
                node_color.append('#FFD700')  # Yellow
                node_size.append(25)
        else:
            # Green for unaffected nodes
            version = G.nodes[node].get('version', 'unknown')
            node_text.append(
                f"<b>{node}</b><br>"
                f"Version: {version}<br>"
                f"Status: <b>Not Affected</b><br>"
                f"(Not in dependency chain)"
            )
            node_color.append('#32CD32')  # Green
            node_size.append(20)
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        text=node_labels,
        textposition="top center",
        hovertext=node_text,
        hoverinfo='text',
        marker=dict(
            size=node_size, 
            color=node_color, 
            line=dict(width=2, color='white'),
            opacity=0.9
        ),
        textfont=dict(size=10, color='white'),
        showlegend=False,
        name='Packages'
    )
    
    # Create legend traces (invisible, just for legend)
    legend_traces = [
        go.Scatter(
            x=[None], y=[None],
            mode='markers',
            marker=dict(size=15, color='#FF0000', line=dict(width=2, color='white')),
            name='🔴 HIGH Risk (Vulnerable)',
            showlegend=True
        ),
        go.Scatter(
            x=[None], y=[None],
            mode='markers',
            marker=dict(size=15, color='#FF8C00', line=dict(width=2, color='white')),
            name='🟠 MEDIUM Risk (Direct)',
            showlegend=True
        ),
        go.Scatter(
            x=[None], y=[None],
            mode='markers',
            marker=dict(size=15, color='#FFD700', line=dict(width=2, color='white')),
            name='🟡 LOW Risk (Indirect)',
            showlegend=True
        ),
        go.Scatter(
            x=[None], y=[None],
            mode='markers',
            marker=dict(size=15, color='#32CD32', line=dict(width=2, color='white')),
            name='🟢 Not Affected',
            showlegend=True
        )
    ]
    
    fig = go.Figure(
        data=edge_traces + [node_trace] + legend_traces,
        layout=go.Layout(
            title={
                'text': 'Dependency Risk Propagation Map<br><sub>Hierarchical Layout: Top = Vulnerable Package → Bottom = Dependencies</sub>',
                'x': 0.5,
                'xanchor': 'center',
                'font': dict(size=20)
            },
            showlegend=True,
            legend=dict(
                x=1.02,
                y=1,
                xanchor='left',
                yanchor='top',
                bgcolor='rgba(0,0,0,0.5)',
                bordercolor='white',
                borderwidth=1,
                font=dict(color='white', size=14)
            ),
            hoverlabel=dict(
                bgcolor="white",
                font_size=16,
                font_family="Arial"
            ),
            hovermode='closest',
            margin=dict(b=80, l=80, r=150, t=80),
            xaxis=dict(
                showgrid=True,
                zeroline=True,
                showticklabels=True,
                gridcolor='rgba(128,128,128,0.2)',
                title=dict(
                    text='Dependency Spread →<br><span style="font-size:12px">Left: Affected Packages | Center: Main Chain | Right: Unaffected</span>',
                    font=dict(size=14, color='white')
                ),
                tickfont=dict(color='white', size=12),
                tickmode='linear',
                tick0=-3,
                dtick=1
            ),
            yaxis=dict(
                showgrid=True,
                zeroline=True,
                showticklabels=True,
                gridcolor='rgba(128,128,128,0.2)',
                title=dict(
                    text='← Dependency Depth (Hops from Vulnerability)<br><span style="font-size:12px">Top: Source | Bottom: Indirect</span>',
                    font=dict(size=14, color='white')
                ),
                tickfont=dict(color='white', size=12),
                tickmode='array',
                tickvals=[i * 2 for i in range(max_depth + 2)],
                ticktext=[f'Depth {max_depth - i}' for i in range(max_depth + 2)]
            ),
            height=700,
            plot_bgcolor='#0E1117',
            paper_bgcolor='#0E1117'
        )
    )
    
    return fig

# Main app
def main():
    # Main header with modern styling
    st.markdown("<h1>🛡️ CVE Impact Visualizer</h1>", unsafe_allow_html=True)
    st.markdown("<p class='subtitle'>AI-powered security tool for analyzing CVE impact across dependency graphs</p>", unsafe_allow_html=True)
    
    # Show AI suggestions banner if available
    if st.session_state.ai_suggestions and not st.session_state.analysis_done:
        st.info(f"""
        🤖 **AI Risk Advisor Active:** {len(st.session_state.ai_suggestions)} high-priority 
        vulnerabilities detected in your selected project. Check the sidebar for suggestions.
        """)
    
    # Sidebar
    with st.sidebar:
        st.markdown("<h2>⚙️ Configuration</h2>", unsafe_allow_html=True)
        
        # Project Selection FIRST (needed for AI suggestions)
        st.markdown("<h3>📦 Project Selection</h3>", unsafe_allow_html=True)
        
        mock_graphs = load_mock_graphs()
        project_options = ["Select..."] + list(mock_graphs.keys())
        selected_project = st.selectbox("Choose Project", project_options)
        
        uploaded_file = st.file_uploader("Or Upload Custom Graph (JSON)", type=['json'])
        
        # AI Risk Advisor Section
        st.markdown("---")
        st.markdown("<h3>🤖 AI Risk Advisor</h3>", unsafe_allow_html=True)
        
        # Generate suggestions when project is selected
        if selected_project != "Select...":
            graph_data = mock_graphs[selected_project]
            suggestions = suggest_vulnerabilities(graph_data)
            st.session_state.ai_suggestions = suggestions
            
            if suggestions:
                st.markdown("**💡 Suggested Vulnerabilities:**")
                st.caption("Based on your dependency graph analysis")
                
                for i, suggestion in enumerate(suggestions):
                    severity_emoji = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }
                    emoji = severity_emoji.get(suggestion['severity'], '⚪')
                    
                    # Create a container for each suggestion
                    with st.container():
                        st.markdown(f"""
                        <div style='background: white; padding: 1rem; border-radius: 8px; 
                                    border-left: 4px solid #3b82f6; margin-bottom: 0.75rem; 
                                    box-shadow: 0 1px 3px rgba(0,0,0,0.1);'>
                            <div style='font-size: 1.1rem; font-weight: 600; color: #1f2937;'>
                                {emoji} {suggestion['package']}
                            </div>
                            <div style='font-size: 0.95rem; color: #6b7280; margin-top: 0.25rem;'>
                                {suggestion['cve']} - {suggestion['reason'][:50]}...
                            </div>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        if st.button("Select", key=f"suggest_{i}", use_container_width=True, type="primary"):
                            st.session_state.selected_cve = suggestion['cve']
                            st.session_state.selected_package = suggestion['package']
                            st.rerun()
            else:
                st.info("No high-priority vulnerabilities detected in this project.")
        else:
            st.info("👈 Select a project to see AI-suggested vulnerabilities")
        
        # CVE Input
        st.markdown("---")
        st.markdown("<h3>🔒 Manual CVE Lookup</h3>", unsafe_allow_html=True)
        
        # Use selected CVE from AI suggestions if available
        default_cve = st.session_state.selected_cve if st.session_state.selected_cve else "CVE-2021-44228"
        
        cve_id = st.text_input(
            "Enter CVE ID", 
            value=default_cve, 
            placeholder="e.g., CVE-2024-1234",
            help="Enter any CVE ID - will search OSV.dev, NVD, and local database"
        )
        
        analyze_btn = st.button("🚀 Analyze Impact", type="primary", use_container_width=True)
        
        st.markdown("---")
        st.markdown("### 📊 Risk Levels")
        st.markdown("🔴 **HIGH** - Score ≥ 6")
        st.markdown("🟠 **MEDIUM** - Score 4-5")
        st.markdown("🟡 **LOW** - Score < 4")
    
    # Analysis
    if analyze_btn:
        # Reset fix status for new analysis
        st.session_state.fix_applied = False
        st.session_state.fix_rejected = False
        st.session_state.analysis_done = True
        
        if not cve_id:
            st.error("Please enter a CVE ID")
            return
        
        # Load graph
        graph_data = None
        if uploaded_file:
            try:
                graph_data = json.load(uploaded_file)
                st.success(f"✅ Loaded custom graph from {uploaded_file.name}")
            except:
                st.error("Invalid JSON file")
                return
        elif selected_project != "Select...":
            graph_data = mock_graphs[selected_project]
        else:
            st.warning("Please select a project or upload a graph")
            return
        
        with st.spinner("🔍 Fetching CVE data from multiple sources..."):
            vuln_info = get_vulnerable_package(cve_id)
        
        if not vuln_info:
            st.error(f"❌ CVE {cve_id} not found in any database (OSV.dev, NVD, or local)")
            st.info("""
            **💡 Tips:**
            - Verify the CVE ID format (e.g., CVE-2021-44228)
            - Try searching by package name instead
            - Check if the CVE is recent (may not be in databases yet)
            - Use the "Package Name" search to find CVEs
            """)
            return
        
        package, severity, cvss_score, source = vuln_info
        
        # Build graph
        G = build_graph(graph_data)
        
        if package not in G.nodes():
            st.warning(f"⚠️ Package '{package}' not found in selected project graph.")
            st.info(f"""
            **Available packages in {selected_project if selected_project != "Select..." else "this graph"}:**
            {', '.join(sorted(G.nodes()))}
            
            **Possible reasons:**
            - The vulnerable package is not a dependency of this project
            - Package name mismatch (OSV.dev uses different naming than your graph)
            - This project doesn't use the affected ecosystem
            
            **What you can do:**
            - Try a different project that uses this package
            - Check if the package exists under a different name in your graph
            - Use a CVE that affects packages in this project
            """)
            return
        
        # Propagate risk
        with st.spinner("📊 Calculating risk propagation..."):
            risk_data = propagate_risk(G, package, severity)
        
        # Metrics Dashboard with larger cards
        st.markdown("<br>", unsafe_allow_html=True)
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("🎯 CVE ID", cve_id, help="Common Vulnerabilities and Exposures identifier")
        with col2:
            st.metric("📦 Vulnerable Package", package, help="Affected software package")
        with col3:
            st.metric("⚠️ Severity", severity, delta=f"CVSS: {cvss_score}", help="Risk severity level")
        
        col4, col5, col6 = st.columns(3)
        with col4:
            blast_radius = (len(risk_data) / len(G.nodes())) * 100
            st.metric("💥 Blast Radius", f"{blast_radius:.1f}%", help="Percentage of affected components")
        with col5:
            high_count = sum(1 for rd in risk_data.values() if rd['risk_level'] == 'HIGH')
            st.metric("🔴 High Risk Components", high_count, help="Components at high risk")
        with col6:
            st.metric("📡 Data Source", source, help="Where the CVE data was found")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        # Tabs with better styling
        tab1, tab2, tab3, tab4 = st.tabs(["📈 Visualization", "📋 Risk Table", "📊 Summary", "🛠️ Fix Simulation"])
        
        with tab1:
            st.markdown("<h2>Dependency Risk Map</h2>", unsafe_allow_html=True)
            
            # Explanation of the visualization
            st.info("""
            **📊 How to Read This Graph:**
            
            **Y-Axis (Vertical - Dependency Depth)**:
            - **Top (Depth 0)**: Vulnerable package - the source of the security issue
            - **Middle (Depth 1)**: Direct dependencies - packages that directly use the vulnerable package
            - **Bottom (Depth 2+)**: Indirect dependencies - packages affected through the chain
            
            **X-Axis (Horizontal - Dependency Spread)**:
            - **Left/Center**: Packages in the vulnerability chain (affected)
            - **Right Side (x > 2)**: Unaffected packages - not connected to the vulnerability
            
            **Lines/Edges**: Show dependency relationships (who depends on whom)
            - **Red lines**: Connect packages in the vulnerability chain
            - **Gray lines**: Other dependencies
            
            **Legend**: Shows risk levels with color coding (see right side of graph)
            
            💡 **Tip**: Hover over any node to see detailed information!
            """)
            
            fig = create_risk_graph(G, risk_data, package)
            st.plotly_chart(fig, use_container_width=True)
        
        with tab2:
            st.markdown("<h2>Affected Components</h2>", unsafe_allow_html=True)
            
            table_data = []
            for node, rd in sorted(risk_data.items(), key=lambda x: (-x[1]['risk_score'], x[0])):
                risk_emoji = {'HIGH': '🔴', 'MEDIUM': '🟠', 'LOW': '🟡'}
                table_data.append({
                    'Component': node,
                    'Version': rd['version'],
                    'Depth': rd['depth'],
                    'Type': rd['type'].upper(),
                    'Risk Score': rd['risk_score'],
                    'Risk Level': f"{risk_emoji[rd['risk_level']]} {rd['risk_level']}"
                })
            
            df = pd.DataFrame(table_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
            
            csv = df.to_csv(index=False)
            st.download_button(
                "📥 Download Report (CSV)",
                csv,
                f"cve_impact_{cve_id}.csv",
                "text/csv",
                key=f"download_csv_{cve_id}_{len(risk_data)}"
            )
        
        with tab3:
            st.markdown("<h2>Impact Summary</h2>", unsafe_allow_html=True)
            
            high_count = sum(1 for rd in risk_data.values() if rd['risk_level'] == 'HIGH')
            medium_count = sum(1 for rd in risk_data.values() if rd['risk_level'] == 'MEDIUM')
            low_count = sum(1 for rd in risk_data.values() if rd['risk_level'] == 'LOW')
            
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("🔴 High Risk", high_count)
            with col_b:
                st.metric("🟠 Medium Risk", medium_count)
            with col_c:
                st.metric("🟡 Low Risk", low_count)
            
            st.markdown("---")
            
            # Detailed breakdown by risk level
            st.markdown("### 📊 Risk Breakdown")
            
            if high_count > 0:
                with st.expander(f"🔴 High Risk Components ({high_count})", expanded=True):
                    high_risk_items = [node for node, rd in risk_data.items() if rd['risk_level'] == 'HIGH']
                    for item in high_risk_items:
                        st.markdown(f"- **{item}** (v{risk_data[item]['version']}) - Depth: {risk_data[item]['depth']}")
            
            if medium_count > 0:
                with st.expander(f"🟠 Medium Risk Components ({medium_count})", expanded=True):
                    medium_risk_items = [node for node, rd in risk_data.items() if rd['risk_level'] == 'MEDIUM']
                    for item in medium_risk_items:
                        st.markdown(f"- **{item}** (v{risk_data[item]['version']}) - Depth: {risk_data[item]['depth']}")
            
            if low_count > 0:
                with st.expander(f"🟡 Low Risk Components ({low_count})", expanded=True):
                    low_risk_items = [node for node, rd in risk_data.items() if rd['risk_level'] == 'LOW']
                    for item in low_risk_items:
                        st.markdown(f"- **{item}** (v{risk_data[item]['version']}) - Depth: {risk_data[item]['depth']}")
            
            st.markdown("---")
            st.markdown("### 🎯 Detailed Recommendations")
            
            # Get version recommendations based on CVE
            version_recommendations = {
                "log4j-core": {"vulnerable": "2.14.1", "safe": "2.17.1", "min_safe": "2.17.0"},
                "log4j-api": {"vulnerable": "2.14.1", "safe": "2.17.1", "min_safe": "2.17.0"},
                "lodash": {"vulnerable": "4.17.19", "safe": "4.17.21", "min_safe": "4.17.21"},
                "urllib3": {"vulnerable": "1.26.5", "safe": "1.26.18", "min_safe": "1.26.18"},
                "pip": {"vulnerable": "21.3.1", "safe": "23.3.0", "min_safe": "22.0.0"},
                "struts2-core": {"vulnerable": "2.5.26", "safe": "2.5.33", "min_safe": "2.5.33"},
                "spring-beans": {"vulnerable": "5.3.18", "safe": "5.3.37", "min_safe": "5.3.37"},
                "jquery": {"vulnerable": "3.4.1", "safe": "3.7.1", "min_safe": "3.5.0"},
                "xml2js": {"vulnerable": "0.4.23", "safe": "0.6.2", "min_safe": "0.5.0"},
                "requests": {"vulnerable": "2.28.0", "safe": "2.31.0", "min_safe": "2.31.0"},
                "flask": {"vulnerable": "2.0.1", "safe": "3.0.0", "min_safe": "2.3.0"},
                "django": {"vulnerable": "3.2.5", "safe": "4.2.0", "min_safe": "3.2.23"}
            }
            
            if high_count > 0:
                st.error(f"**🚨 URGENT ACTION REQUIRED**: {high_count} critical components affected")
                
                st.markdown("#### Immediate Actions:")
                
                # Primary vulnerable package
                if package in version_recommendations:
                    rec = version_recommendations[package]
                    st.markdown(f"""
                    **1. Upgrade Vulnerable Package: `{package}`**
                    - Current version: `{rec['vulnerable']}`
                    - Recommended version: `{rec['safe']}`
                    - Minimum safe version: `{rec['min_safe']}`
                    
                    ```bash
                    # Python (pip)
                    pip install {package}>={rec['safe']}
                    
                    # Node.js (npm)
                    npm install {package}@{rec['safe']}
                    
                    # Java (Maven)
                    <dependency>
                        <groupId>org.apache.logging.log4j</groupId>
                        <artifactId>{package}</artifactId>
                        <version>{rec['safe']}</version>
                    </dependency>
                    ```
                    """)
                else:
                    st.markdown(f"""
                    **1. Upgrade Vulnerable Package: `{package}`**
                    - Check official security advisories for patched version
                    - Visit: https://osv.dev or https://nvd.nist.gov
                    """)
                
                st.markdown(f"""
                **2. Review High-Risk Dependencies ({high_count} components)**
                - All {high_count} high-risk components should be audited
                - Check if updates are available for each dependency
                - Test thoroughly in staging environment before production
                """)
                
                st.markdown("""
                **3. Security Scanning**
                ```bash
                # Python
                pip-audit
                safety check
                
                # Node.js
                npm audit
                npm audit fix
                
                # Java
                mvn dependency-check:check
                ```
                """)
            
            if medium_count > 0:
                st.warning(f"**⚠️ MODERATE PRIORITY**: {medium_count} components at medium risk")
                
                st.markdown(f"""
                #### Medium Priority Actions:
                - **{medium_count} components** are indirectly affected (1 hop from vulnerability)
                - Plan upgrade within next sprint/release cycle
                - Monitor for security advisories
                - Consider updating parent dependencies to pull in fixes
                """)
            
            if low_count > 0:
                st.info(f"**ℹ️ LOW PRIORITY**: {low_count} components at low risk")
                
                st.markdown(f"""
                #### Low Priority Actions:
                - **{low_count} components** are distantly affected (2+ hops)
                - Include in regular maintenance updates
                - Monitor for cascading vulnerabilities
                - No immediate action required unless other factors present
                """)
            
            st.markdown("---")
            st.markdown("### 📋 Action Checklist")
            
            st.markdown(f"""
            - [ ] Upgrade `{package}` to patched version
            - [ ] Run security audit tools (pip-audit, npm audit, etc.)
            - [ ] Review all {high_count} high-risk dependencies
            - [ ] Test changes in staging environment
            - [ ] Update CI/CD pipeline to block vulnerable versions
            - [ ] Document changes in security log
            - [ ] Schedule follow-up scan in 30 days
            - [ ] Notify security team and stakeholders
            """)
        
        with tab4:
            st.markdown("<h2>🛠️ Fix Simulation & Control</h2>", unsafe_allow_html=True)
            
            # Show AI explanation if this was an AI-suggested CVE
            if st.session_state.selected_cve == cve_id and st.session_state.selected_package == package:
                st.info(f"""
                **🤖 AI Risk Advisor Insight:**
                This vulnerability was suggested because `{package}` is a {G.nodes[package].get('type', 'standard')} 
                dependency in your project. Security-critical packages like this require immediate attention 
                when vulnerabilities are discovered.
                """)
            
            st.markdown("---")
            st.markdown("### 📊 Impact Analysis")
            
            col_x, col_y = st.columns(2)
            
            with col_x:
                st.markdown("#### ⚠️ Before Fix")
                st.metric("Affected Components", len(risk_data))
                st.metric("High Risk", high_count)
                st.metric("Blast Radius", f"{blast_radius:.1f}%")
            
            with col_y:
                st.markdown("#### ✅ After Fix")
                st.metric("Affected Components", 0, delta=f"-{len(risk_data)}", delta_color="inverse")
                st.metric("High Risk", 0, delta=f"-{high_count}", delta_color="inverse")
                st.metric("Blast Radius", "0.0%", delta=f"-{blast_radius:.1f}%", delta_color="inverse")
            
            st.markdown("---")
            st.markdown("### 🎯 Fix Decision")
            
            # Show current status first
            if st.session_state.fix_applied:
                st.success("✅ Fix Status: APPLIED - System is secured")
            elif st.session_state.fix_rejected:
                st.error("❌ Fix Status: REJECTED - System remains vulnerable")
            else:
                st.info("⏳ Fix Status: PENDING - Awaiting decision")
            
            st.markdown("")  # Add spacing
            
            # Fix control buttons
            col_btn1, col_btn2, col_btn3 = st.columns([2, 2, 1])
            
            with col_btn1:
                apply_fix_btn = st.button("✅ Apply Fix", type="primary", use_container_width=True, key=f"apply_fix_{cve_id}")
            
            with col_btn2:
                reject_fix_btn = st.button("❌ Reject Fix", use_container_width=True, key=f"reject_fix_{cve_id}")
            
            # Handle Apply Fix
            if apply_fix_btn:
                st.session_state.fix_applied = True
                st.session_state.fix_rejected = False
                st.balloons()
                st.toast("✅ Fix applied! Refreshing...", icon="✅")
                st.rerun()  # Force rerun to show updated status
            
            # Handle Reject Fix
            if reject_fix_btn:
                st.session_state.fix_applied = False
                st.session_state.fix_rejected = True
                st.toast("❌ Fix rejected! Refreshing...", icon="❌")
                st.rerun()  # Force rerun to show updated status
            
            # Show detailed messages based on status
            if st.session_state.fix_applied:
                st.success(f"""
                ### ✅ Fix Applied Successfully!
                
                **Patch Details:**
                - Package: `{package}` upgraded to secure version
                - Components secured: {len(risk_data)}
                - Vulnerability mitigated: {cve_id}
                - Severity reduced: {severity} → NONE
                
                **Next Steps:**
                1. Run security audit: `pip-audit` or `npm audit`
                2. Test in staging environment
                3. Update CI/CD pipeline to block vulnerable versions
                4. Deploy to production
                5. Document the fix in your security log
                
                **Recommended Commands:**
                ```bash
                # Python
                pip install {package}>=<safe_version>
                pip-audit
                
                # Node.js
                npm install {package}@latest
                npm audit fix
                
                # Java (Maven)
                # Update pom.xml with patched version
                mvn dependency:tree
                ```
                """)
            
            # Handle Reject Fix
            if st.session_state.fix_rejected:
                st.warning(f"""
                ### ⚠️ Fix Rejected
                
                **Status:**
                - Original dependency graph maintained
                - Vulnerability remains: {cve_id}
                - {len(risk_data)} components still at risk
                
                **⚠️ Security Risk:**
                By rejecting this fix, your application remains vulnerable to {severity} severity 
                attacks. This could lead to:
                - Data breaches
                - System compromise
                - Compliance violations
                - Reputational damage
                
                **Alternative Actions:**
                1. Implement compensating controls (WAF, network segmentation)
                2. Monitor for exploitation attempts
                3. Plan fix for next maintenance window
                4. Document risk acceptance with stakeholders
                5. Set reminder to revisit this decision
                
                **Risk Acceptance Required:**
                If you choose to proceed without fixing, ensure proper risk acceptance 
                documentation is in place per your organization's security policy.
                """)
    
    else:
        st.info("👈 Enter a CVE ID and select a project to begin analysis")
        
        # Show categorized CVE reference
        with st.expander("📚 Sample CVE IDs to Try"):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 🔥 Critical Severity")
                st.markdown("- **CVE-2021-44228** - Log4Shell")
                st.markdown("- **CVE-2022-22965** - Spring4Shell")
                st.markdown("- **CVE-2017-5638** - Equifax breach")
                
                st.markdown("### 🔴 High Severity")
                st.markdown("- **CVE-2020-8203** - lodash")
                st.markdown("- **CVE-2022-42969** - pip")
                st.markdown("- **CVE-2021-45105** - Log4j DoS")
            
            with col2:
                st.markdown("### 🟠 Medium Severity")
                st.markdown("- **CVE-2021-23336** - urllib3")
                st.markdown("- **CVE-2019-11324** - urllib3")
                st.markdown("- **CVE-2019-10744** - jQuery")
                
                st.markdown("### 💡 How to Use")
                st.markdown("1. Copy any CVE ID above")
                st.markdown("2. Paste in the CVE ID field")
                st.markdown("3. Select matching project")
                st.markdown("4. Click Analyze Impact")
        
        with st.expander("📊 Available Project Templates"):
            st.markdown("""
            - **web_app_project** - Flask + requests (Python) - Shows 🔴🟠🟡
            - **data_science_project** - Pandas + numpy (Python) - Shows 🔴🟠🟡
            - **api_project** - FastAPI stack (Python) - Shows 🔴🟠🟡
            - **django_project** - Django + Celery (Python) - Shows 🔴🟠🟡
            - **java_enterprise_project** - Spring + Log4j + Struts (Java) - Shows 🔴🟠🟡
            - **nodejs_webapp_project** - Express + lodash + jQuery (Node.js) - Shows 🔴🟠🟡
            - **python_data_pipeline** - requests + urllib3 + pip (Python) - Shows 🔴🟠🟡
            - **comprehensive_app** - Full stack with 15 packages (Python) - Shows 🔴🟠🟡🟢
            
            💡 **Tip**: Use `comprehensive_app` with CVE-2021-23336 to see all 4 colors!
            """)

if __name__ == "__main__":
    main()
