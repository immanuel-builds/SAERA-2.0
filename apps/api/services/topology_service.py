class TopologyBuilderService:
    """
    Translates flat scan telemetry into a graph-based relationship model.
    Designed to power interactive Vis.js visualizations.
    """

    @staticmethod
    def build_scan_graph(scan):
        """
        Converts scan results into a nodes/edges structure.
        """
        nodes = []
        edges = []
        
        # 1. Identity Node (The Core Target)
        target_id = f"target_{scan.target.id}"
        nodes.append({
            "id": target_id,
            "label": scan.target.target,
            "group": "target",
            "title": f"Target: {scan.target.name}",
            "value": 20, # Size relative to significance
        })
        
        # 2. Vector Nodes (The Active Ports/Services)
        services = scan.port_results.all()
        for svc in services:
            svc_id = f"svc_{svc.id}"
            nodes.append({
                "id": svc_id,
                "label": f"{svc.port}/{svc.protocol}",
                "group": "service",
                "title": f"Service: {svc.service}\nVersion: {svc.service_version or 'Unknown'}",
                "value": 15,
                "is_suppressed": svc.is_suppressed,
                "lifecycle_state": svc.lifecycle_state
            })
            # Connect vector to target
            edges.append({
                "from": target_id,
                "to": svc_id,
                "label": "exposes",
                "arrows": "to",
                "color": {"color": "#6B6B6B", "opacity": 0.4}
            })
            
            # 3. Intelligence Nodes (The Vulnerabilities/Findings)
            vulns = scan.vulnerabilities.filter(port=svc.port)
            for vuln in vulns:
                vuln_id = f"vuln_{vuln.id}"
                
                # Determine node color based on severity
                severity_colors = {
                    'critical': '#9F3B32', # Seal Red
                    'high': '#D97706',
                    'medium': '#EAB308',
                    'low': '#4E6B57', # Bamboo Green
                    'info': '#6B6B6B'
                }
                
                nodes.append({
                    "id": vuln_id,
                    "label": vuln.title[:20] + "...",
                    "group": "vulnerability",
                    "title": f"[{vuln.severity.upper()}] {vuln.title}\nCVSS: {vuln.cvss_score or 'N/A'}",
                    "color": severity_colors.get(vuln.severity, '#6B6B6B'),
                    "value": 10 + (vuln.cvss_score or 0),
                    "is_suppressed": vuln.is_suppressed,
                    "lifecycle_state": vuln.lifecycle_state
                })
                # Connect finding to vector
                edges.append({
                    "from": svc_id,
                    "to": vuln_id,
                    "label": "contains",
                    "arrows": "to",
                    "dashes": True if vuln.severity in ['critical', 'high'] else False
                })

        return {"nodes": nodes, "edges": edges}
