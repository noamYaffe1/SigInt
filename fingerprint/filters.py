"""Shared filtering utilities for fingerprint analysis."""
import re
from typing import Dict


# Generic patterns to exclude from fingerprints
GENERIC_PATTERNS = [
    # HTML structure
    r'<html\s+lang=',
    r'<meta\s+http-equiv=',
    r'<meta\s+charset=',
    r'<meta\s+name="viewport"',
    r'<meta\s+name="robots"',
    r'<!DOCTYPE\s+html>',
    r'<div\s+class=',
    r'<span\s+class=',
    
    # Common headers/meta
    r'X-UA-Compatible',
    r'Content-Type',
    r'charset=UTF-8',
    
    # Generic JavaScript
    r'^dataLayer\s*=',  # Google Tag Manager
    r'window\.',
    r'document\.',
    
    # Frontend frameworks and libraries (NOT unique to any app)
    r'^jquery$',
    r'^bootstrap$',
    r'^font-?awesome$',
    r'^react$',
    r'^angular$',
    r'^vue$',
    r'^tailwind',
    r'^materialize',
    r'^foundation$',
    r'^bulma$',
    r'^semantic-ui',
    r'^normalize',
    r'^reset\.css',
    r'^ng-app$',        # Angular 1.x
    r'^ng-controller$',
    r'^ng-model$',
    r'^ng-view$',
    r'^ng-repeat$',
    r'^v-app$',         # Vue.js
    r'^v-model$',
    r'^v-if$',
    r'^v-for$',
    r'^data-reactroot$',  # React
    r'^data-reactid$',
    r'^__next$',        # Next.js
    r'^__nuxt$',        # Nuxt.js
    r'^app-root$',      # Angular 2+
    r'^mat-',           # Angular Material
    r'^md-',            # Material Design
    r'^mdc-',           # Material Components
    r'^btn$',
    r'^fa-',            # Font Awesome
    r'^glyphicon',
    r'^icon-',
    r'polyfill',
    r'webpack',
    r'main\.\w+\.js$',
    r'vendor\.\w+\.js$',
    r'runtime\.\w+\.js$',
    r'chunk\.\w+\.js$',
    
    # Common CMS/frameworks
    r'/wp-content/',
    r'/wp-includes/',
    r'/xmlrpc\.php',
    r'/node_modules/',
    r'/vendor/',
    
    # Generic paths
    r'^/admin$',
    r'^/api$',
    r'^/login$',
    r'^/home$',
    r'^/index$',
    
    # Generic attributes
    r'class="',
    r'id="',
    r'style="',
    r'no-js',
]

# Very common terms that should NEVER be used as query terms
# These are matched as whole words (case-insensitive)
QUERY_BLACKLIST = {
    # Common page elements
    'login', 'logout', 'register', 'signup', 'sign up', 'sign in',
    'password', 'email', 'username', 'submit', 'search', 'home',
    'index', 'welcome', 'dashboard', 'admin', 'settings', 'profile',
    'contact', 'about', 'help', 'faq', 'terms', 'privacy',
    
    # Common frameworks/libraries (will match millions of sites)
    'bootstrap', 'jquery', 'font-awesome', 'fontawesome', 'react',
    'angular', 'vue', 'tailwind', 'materialize', 'foundation',
    'twitter', 'facebook', 'google', 'github', 'linkedin',
    
    # Common CSS/JS patterns
    'normalize', 'reset', 'polyfill', 'vendor', 'bundle', 'chunk',
    'main.js', 'app.js', 'style.css', 'main.css',
    
    # Common meta content
    'utf-8', 'viewport', 'robots', 'description', 'keywords',
    
    # Single common words
    'the', 'and', 'for', 'with', 'from', 'that', 'this',
}

# Backend-only patterns that won't be visible in HTTP responses
BACKEND_ONLY_PATTERNS = [
    # PHP/Code internals
    r'function\s+\w+',       # PHP/JS function names
    r'class\s+\w+',          # PHP/JS class names
    r'\$\w+',                # PHP variables
    r'require\s+',           # PHP require/include
    r'include\s+',
    r'use\s+\w+\\',          # PHP namespace use
    
    # Package managers / Dependencies
    r'composer',
    r'dependency',
    r'package\.json',
    r'requirements\.txt',
    r'npm',
    r'yarn',
    r'gradle',
    r'maven',
    r'pip',
    
    # Code comments
    r'//\s*',
    r'/\*',
    r'\*/',
    
    # Internal paths not accessible via HTTP
    r'vendor/',
    r'node_modules/',
    r'src/',
    r'lib/',
    r'tests/',
    r'__pycache__',
]


def is_query_blacklisted(value: str) -> bool:
    """Check if a query value is too generic to be useful.
    
    Args:
        value: The query value to check
        
    Returns:
        True if the value is blacklisted/too generic
    """
    if not value or len(value) < 3:
        return True
    
    value_lower = value.lower().strip()
    
    # Direct match against blacklist
    if value_lower in QUERY_BLACKLIST:
        return True
    
    # Check if value is just a common word
    if len(value_lower) <= 10 and value_lower in QUERY_BLACKLIST:
        return True
    
    # Check if value matches generic patterns
    for pattern in GENERIC_PATTERNS:
        if re.match(pattern, value_lower):
            return True
    
    return False


def filter_generic_patterns(analysis: Dict) -> Dict:
    """Post-process LLM output to remove generic patterns that slipped through.
    
    Args:
        analysis: LLM analysis dict with page_signatures, distinctive_features
        
    Returns:
        Filtered analysis dict
    """
    app_name = analysis.get('app_name', '')
    
    def is_generic(pattern: str) -> bool:
        """Check if pattern is too generic."""
        if not pattern or len(pattern) < 3:
            return True
        if len(pattern) > 100:  # Too long patterns are likely HTML
            return True
        
        # Check against generic pattern list
        for generic in GENERIC_PATTERNS:
            if re.search(generic, pattern, re.IGNORECASE):
                # BUT: if pattern also contains app name, keep it
                if app_name and len(app_name) > 3:
                    if app_name.lower() in pattern.lower():
                        return False  # Keep it - has app name
                return True
        
        return False
    
    def is_backend_only(text: str) -> bool:
        """Check if this describes a backend-only feature not visible in HTTP."""
        if not text:
            return False
        text_lower = text.lower()
        
        # Check for backend-only keywords
        for backend_pattern in BACKEND_ONLY_PATTERNS:
            if re.search(backend_pattern, text, re.IGNORECASE):
                return True
        
        # Check for common backend-only phrases
        backend_phrases = [
            'function',
            'composer',
            'dependency',
            'php variable',
            'class name',
            'method',
            'internal',
            'backend',
            'server-side',
        ]
        for phrase in backend_phrases:
            if phrase in text_lower:
                return True
        
        return False
    
    # Filter page signatures
    if 'page_signatures' in analysis:
        for sig in analysis['page_signatures']:
            if 'body_patterns' in sig:
                sig['body_patterns'] = [
                    p for p in sig['body_patterns'] 
                    if not is_generic(p)
                ]
    
    # Filter distinctive features - remove backend-only features
    if 'distinctive_features' in analysis:
        analysis['distinctive_features'] = [
            f for f in analysis['distinctive_features']
            if not is_generic(f) and not is_backend_only(f) and len(f) > 10
        ]
    
    return analysis

