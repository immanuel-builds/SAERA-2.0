import json
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from apps.api.services.dashboard_service import DashboardService
from apps.api.services.intelligence_service import IntelligenceService

def landing(request):
    """Render public landing page. If authenticated, redirect to dashboard."""
    if request.user.is_authenticated:
        from django.shortcuts import redirect
        return redirect('dashboard')
    return render(request, 'landing.html')

@login_required
def dashboard(request):
    """
    Main observatory dashboard view.
    Orchestrated via the DashboardService intelligence layer.
    """
    context = DashboardService.get_dashboard_context(request.user)
    return render(request, 'dashboard/index.html', context)

@login_required
def network_map(request):
    """
    Network Topology Visualization view.
    Leverages the TopologyBuilderService for relationship modeling.
    """
    # For the global map, we aggregate all relevant scans
    # In a production scenario, we might want to filter this by active scans
    from apps.scanner.models import ScanJob
    from apps.api.services.topology_service import TopologyBuilderService
    
    if request.user.is_admin:
        latest_scans = ScanJob.objects.filter(status='completed')[:20]
    else:
        latest_scans = ScanJob.objects.filter(initiated_by=request.user, status='completed')[:10]

    all_nodes = []
    all_edges = []
    
    # Observatory Central Node
    all_nodes.append({
        "id": "saera_core",
        "label": "SAERA Observatory",
        "group": "core",
        "value": 30
    })

    for scan in latest_scans:
        graph = TopologyBuilderService.build_scan_graph(scan)
        all_nodes.extend(graph['nodes'])
        all_edges.extend(graph['edges'])
        
        # Connect target to Observatory
        all_edges.append({
            "from": "saera_core",
            "to": f"target_{scan.target.id}",
            "color": {"opacity": 0.2}
        })

    # De-duplicate nodes
    unique_nodes = {node['id']: node for node in all_nodes}.values()

    context = {
        "nodes_json": json.dumps(list(unique_nodes)),
        "edges_json": json.dumps(all_edges),
    }
    
    return render(request, 'dashboard/network_map.html', context)
