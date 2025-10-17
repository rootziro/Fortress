### Password Strength Analyzer, Calculating Entropy, Detects weak patterns,
### Estimates time to crack using common attack methods, and provides feedback.

import math
import re
from collections import Counter
from typing import Dict, List
from zxcvbn import zxcvbn