"""
Password Generator module for Fortress.
Implements AI-driven password generation and strength analysis.
"""

import random
import string
import zxcvbn
from typing import Dict, Optional
from dataclasses import dataclass

@dataclass
class PasswordPolicy:
    """Password policy configuration."""
    min_length: int = 16
    max_length: int = 32
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    min_entropy: float = 70.0  # Minimum entropy score required
    excluded_chars: str = '"\'\\`'  # Characters to exclude

class AIPasswordGenerator:
    """AI-driven password generator with strength analysis."""
    
    def __init__(self, policy: Optional[PasswordPolicy] = None):
        """Initialize the generator with optional custom policy."""
        self.policy = policy or PasswordPolicy()
        self._char_sets = {
            'uppercase': string.ascii_uppercase,
            'lowercase': string.ascii_lowercase,
            'digits': string.digits,
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        # Filter out excluded characters from all charsets
        for char in self.policy.excluded_chars:
            for charset in self._char_sets.values():
                self._char_sets[charset] = charset.replace(char, '')

    def generate_password(self, context: Optional[Dict[str, str]] = None) -> str:
        """
        Generate a strong password using AI-driven analysis.
        
        Args:
            context: Optional dictionary containing context about the target service
                    (e.g., {'service': 'github', 'username': 'user@example.com'})
        
        Returns:
            A strong password meeting the policy requirements
        """
        while True:
            # Generate initial password meeting basic requirements
            length = random.randint(self.policy.min_length, self.policy.max_length)
            password = self._generate_candidate(length)
            
            # Analyze password strength using zxcvbn
            strength = self.analyze_strength(password, context)
            
            if (strength['entropy'] >= self.policy.min_entropy and
                self._meets_requirements(password)):
                return password

    def _generate_candidate(self, length: int) -> str:
        """Generate a password candidate of specified length."""
        all_chars = ''
        if self.policy.require_uppercase:
            all_chars += self._char_sets['uppercase']
        if self.policy.require_lowercase:
            all_chars += self._char_sets['lowercase']
        if self.policy.require_digits:
            all_chars += self._char_sets['digits']
        if self.policy.require_special:
            all_chars += self._char_sets['special']
        
        # Ensure at least one character from each required set
        password = []
        if self.policy.require_uppercase:
            password.append(random.choice(self._char_sets['uppercase']))
        if self.policy.require_lowercase:
            password.append(random.choice(self._char_sets['lowercase']))
        if self.policy.require_digits:
            password.append(random.choice(self._char_sets['digits']))
        if self.policy.require_special:
            password.append(random.choice(self._char_sets['special']))
            
        # Fill remaining length with random characters
        remaining = length - len(password)
        password.extend(random.choice(all_chars) for _ in range(remaining))
        
        # Shuffle the password
        random.shuffle(password)
        return ''.join(password)

    def _meets_requirements(self, password: str) -> bool:
        """Check if password meets all policy requirements."""
        if self.policy.require_uppercase and not any(c.isupper() for c in password):
            return False
        if self.policy.require_lowercase and not any(c.islower() for c in password):
            return False
        if self.policy.require_digits and not any(c.isdigit() for c in password):
            return False
        if self.policy.require_special and not any(c in self._char_sets['special'] for c in password):
            return False
        return True

    def analyze_strength(self, password: str, context: Optional[Dict[str, str]] = None) -> Dict:
        """
        Analyze password strength using zxcvbn.
        
        Args:
            password: The password to analyze
            context: Optional context information to improve analysis
            
        Returns:
            Dictionary containing strength metrics
        """
        user_inputs = []
        if context:
            user_inputs.extend(context.values())
            
        result = zxcvbn(password, user_inputs=user_inputs)
        
        return {
            'score': result['score'],  # 0-4
            'entropy': result['guesses_log10'] * 10,  # Convert to 0-100 scale
            'crack_time': result['crack_times_seconds']['online_no_throttling_10_per_second'],
            'feedback': result['feedback']
        }
