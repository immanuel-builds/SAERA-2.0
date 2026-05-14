from django.shortcuts import render, get_object_or_404
from .models import VulnerabilityReference

def reference_list(request):
    references = VulnerabilityReference.objects.all()
    categories = VulnerabilityReference.objects.values_list('category', flat=True).distinct()
    return render(request, 'knowledge/reference_list.html', {
        'references': references,
        'categories': categories,
    })

def reference_detail(request, slug):
    reference = get_object_or_404(VulnerabilityReference, slug=slug)
    return render(request, 'knowledge/reference_detail.html', {
        'reference': reference,
    })
