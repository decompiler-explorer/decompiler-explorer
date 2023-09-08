from rest_framework.throttling import AnonRateThrottle

from .utils import is_request_from_worker

class AnonRateThrottleSliding(AnonRateThrottle):
    def get_cache_key(self, request, view):
        if is_request_from_worker(request):
            # Do not throttle workers
            return None
        return super().get_cache_key(request, view)

    def throttle_failure(self):
        if len(self.history) >= self.num_requests: # type: ignore
            self.history.pop(-1)
        self.history.insert(0, self.now)
        self.cache.set(self.key, self.history, self.duration)
        return super().throttle_failure()

class AnonBurstRateThrottle(AnonRateThrottleSliding):
    scope = 'anon_burst'

class AnonSustainedRateThrottle(AnonRateThrottleSliding):
    scope = 'anon_sustained'
