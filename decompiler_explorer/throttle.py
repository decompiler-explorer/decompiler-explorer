from rest_framework.throttling import AnonRateThrottle

class AnonBurstRateThrottle(AnonRateThrottle):
    scope = 'anon_burst'

class AnonSustainedRateThrottle(AnonRateThrottle):
    scope = 'anon_sustained'
