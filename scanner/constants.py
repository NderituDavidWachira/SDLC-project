PILLARS = [
    ('endpoint-ide', 'Endpoint/IDE'),
    ('vcs', 'VCS'),
    ('ci-cd', 'CI/CD'),
    ('registry', 'Registry'),
    ('production', 'Production'),
]
PILLAR_NAMES = dict(PILLARS)
SEVERITIES = ['Critical', 'High', 'Medium', 'Low']
SEVERITY_WEIGHTS = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
