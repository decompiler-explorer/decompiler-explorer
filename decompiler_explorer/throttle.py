from rest_framework.throttling import AnonRateThrottle


class AnonRateThrottleSliding(AnonRateThrottle):
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
