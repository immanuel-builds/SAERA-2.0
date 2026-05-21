from django.shortcuts import render, get_object_or_404
from django.db.models import Count
from .models import VulnerabilityReference


def reference_list(request):
    """
    Knowledge Base archive — all reference entries with live search/filter support.
    """
    references = VulnerabilityReference.objects.all()
    categories = VulnerabilityReference.objects.values_list('category', flat=True).distinct()

    # Severity counts for sidebar index
    severity_counts = (
        VulnerabilityReference.objects
        .values('severity')
        .annotate(count=Count('id'))
        .order_by('-count')
    )
    severity_map = {s['severity']: s['count'] for s in severity_counts}

    return render(request, 'knowledge/reference_list.html', {
        'references': references,
        'categories': categories,
        'severity_counts': severity_map,
    })


def reference_detail(request, slug):
    """
    Individual vulnerability reference dossier — full intelligence entry.
    """
    reference = get_object_or_404(VulnerabilityReference, slug=slug)
    return render(request, 'knowledge/reference_detail.html', {
        'reference': reference,
    })
