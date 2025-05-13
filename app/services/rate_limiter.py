from datetime import datetime, timedelta

class RateLimiter:
    """
    Simple in-memory rate limiter implementation
    For production use, consider using Redis or another distributed solution
    """
    def __init__(self):
        self.attempts = {}
        
    def is_limited(self, key, max_attempts=5, window_seconds=300):
        """
        Check if a key has exceeded attempt limits
        
        Args:
            key: Unique identifier for rate limiting
            max_attempts: Maximum attempts allowed
            window_seconds: Time window in seconds
            
        Returns:
            bool: True if rate limited, False otherwise
        """
        now = datetime.utcnow()
        
        # Clean up old entries
        self.attempts = {k: v for k, v in self.attempts.items() 
                        if v['timestamp'] > now - timedelta(seconds=window_seconds)}
        
        if key not in self.attempts:
            self.attempts[key] = {'count': 1, 'timestamp': now}
            return False
            
        if self.attempts[key]['count'] >= max_attempts:
            return True
            
        self.attempts[key]['count'] += 1
        return False
        
    def reset(self, key):
        """Reset attempts for a key"""
        if key in self.attempts:
            del self.attempts[key]