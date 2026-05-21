from django.db import models

class VulnerabilityReference(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Informational'),
    ]

    title = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    category = models.CharField(max_length=100)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    description = models.TextField()
    remediation = models.TextField()
    references = models.TextField(blank=True, help_text="Links to CVEs or security advisories")
    cve_id = models.CharField(max_length=50, unique=True, blank=True, null=True)
    cvss_score = models.FloatField(null=True, blank=True)
    epss_score = models.FloatField(null=True, blank=True, help_text="Exploit Prediction Score (0-1)")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['title']

    def __str__(self):
        return self.title
