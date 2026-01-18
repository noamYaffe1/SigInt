"""LLM prompt templates for different fingerprinting modes.

Modes:
- application: Find all deployments of a software (DVWA, WordPress) - version agnostic
- organization: Find all assets of a company/brand (Monday.com, BSidesTLV) - brand focused
"""


def get_version_rules(include_version: bool) -> str:
    """Get version handling rules based on include_version flag."""
    if include_version:
        return """
**VERSION HANDLING (include_version=True):**
- Include version patterns in fingerprints if they help identify the specific release
- Version patterns should use flexible regex: "v\\d+\\.\\d+" or "202[0-9]" for years
- Include version in title_pattern if it appears in the page title
"""
    else:
        return """
**VERSION HANDLING (include_version=False - DEFAULT):**
- DO NOT include version numbers in body_patterns (v1.0, 2.0, etc.)
- DO NOT include years in body_patterns (2023, 2024, 2025, etc.)
- Title patterns may include app name but avoid version-specific titles
- Focus on patterns that will match ANY version/year of the application
- If you see "App v1.10" use just "App" in body_patterns
- If you see "Conference 2025" use just "Conference" in body_patterns
"""


def get_mode_rules(mode: str) -> str:
    """Get mode-specific rules for the LLM."""
    if mode == "organization":
        return """
**MODE: ORGANIZATION (Brand/Company Discovery)**

Goal: Find ALL web assets belonging to this organization/brand/company.

Key Identifiers to Extract:
✓ Company/brand name (e.g., "BSidesTLV", "Monday.com", "Acme Corp")
✓ Logo and favicon (strong brand identifiers)
✓ Domain patterns (bsidestlv.com, monday.com)
✓ Copyright notices with company name
✓ Brand-specific color schemes or design patterns
✓ Social media handles and brand mentions
✓ Contact information (email domains, addresses)

What to AVOID:
✗ Generic web technologies (React, Bootstrap, WordPress core)
✗ Third-party service integrations (Google Analytics, etc.)
✗ Common web patterns not specific to this brand

Body Patterns Should Include:
- Company/brand name variations
- Domain name without TLD
- Trademark phrases
- Slogan or tagline if distinctive

Example for BSidesTLV:
- Good: ["BSidesTLV", "BSides TLV", "BSides Tel Aviv"]
- Bad: ["2025", "December 11", "Cyber Week"]
"""
    else:  # application mode (default)
        return """
**MODE: APPLICATION (Software Deployment Discovery)**

Goal: Find ALL deployments of this software/application across the internet.

Key Identifiers to Extract:
✓ Application name (e.g., "DVWA", "Jenkins", "Grafana")
✓ Favicon hash (very reliable - same across all deployments)
✓ Unique file paths (/dvwa/, /jenkins/, /api/health)
✓ Application-specific HTML structure
✓ Default configuration patterns
✓ Application-specific error messages

What to AVOID:
✗ Organization/company names (unless part of app name)
✗ Version-specific strings (v1.10, 2.0, etc.)
✗ Deployment-specific configurations
✗ Custom themes or branding overlays
✗ Environment-specific values (dev, prod, staging)

Body Patterns Should Include:
- Application name and variants
- Framework-specific identifiers
- Default strings that ship with the software

Example for DVWA:
- Good: ["DVWA", "Damn Vulnerable Web Application", "vulnerabilities"]
- Bad: ["v1.10", "Development", "localhost"]
"""


def get_iteration_analysis_prompt(
    mode: str,
    include_version: bool,
    base_url: str,
    visited_paths: list,
    discovered_endpoints: int,
    new_content_summary: str,
    iteration: int,
    max_iterations: int
) -> str:
    """Generate the iteration analysis prompt."""
    
    mode_rules = get_mode_rules(mode)
    version_rules = get_version_rules(include_version)
    
    return f"""You are a web application fingerprinting expert conducting recursive discovery on a target.

**Current Status:**
- Iteration: {iteration}/{max_iterations}
- Base URL: {base_url}
- Paths visited so far: {visited_paths}
- Endpoints discovered: {discovered_endpoints}

**New Content Retrieved:**
{new_content_summary}

{mode_rules}

{version_rules}

**CRITICAL RULES FOR FINGERPRINTING:**

1. **Only Suggest REAL Endpoints** - Endpoints to probe MUST be extracted from actual content:
   - Links found in HTML (<a href="...">)
   - Form actions (<form action="...">)
   - Script/API references in JavaScript
   - Paths mentioned in content
   - DO NOT guess common paths like /admin, /api, /config unless you SEE them referenced!

2. **Only Report Real Discovered Endpoints** - Report endpoints that returned 200 OK:
   - DO NOT report 404 (Not Found) or 403 (Forbidden) as endpoints
   - Only report paths that exist and returned valid content

3. **Distinctive Assets Only**:
   - Favicon: always worth fetching if present
   - Logos: only if they have distinctive filenames
   - Images: only if filename suggests uniqueness

**Your Task:**
Analyze the new content and decide:

1. **Application/Organization Identification**: What is this? Name it appropriately for the mode.

2. **Page Signatures (LIMIT TO 2 MAX - ONLY UNIQUE PATTERNS)**: 
   - ONLY extract 1-2 page signatures total (prefer root "/" and one other key page)
   - Title pattern: must contain the APPLICATION NAME, not generic terms
   - Body patterns: ONLY patterns containing APPLICATION NAME or unique identifiers
   
   ✗ ABSOLUTELY NEVER USE THESE AS BODY PATTERNS (they match millions of sites):
     - "Bootstrap", "bootstrap", "Bootstrap core CSS"
     - "font-awesome", "Font Awesome", "fa-"
     - "jQuery", "jquery"
     - "Login", "Logout", "Password", "Email", "Username"
     - "Search", "Home", "Welcome", "Dashboard"
     - "Twitter", "Facebook", "Google", "LinkedIn"
     - "Copyright", "All rights reserved"
     - Any framework name (React, Angular, Vue, Tailwind)
   
   ✓ GOOD EXAMPLES for an app called "Hackazon":
     - "Hackazon" (the app name)
     - "hackazon.webscantest.com" (unique domain reference)
   
   This is MANDATORY for robust fingerprinting!

3. **Discovered Endpoints** (200 OK only): List endpoints with actual content.

4. **Discovered Assets (IMPORTANT - look for logo images!)**: 
   - Look for <img> tags with src containing the APP NAME (e.g., "/images/Hackazon.png")
   - Look for logos, brand images, or icons that are unique to this app
   - Favicon paths (if not standard /favicon.ico)
   - Example: If app is "Hackazon", look for images like "/images/Hackazon.png", "/logo.png"
   - These are valuable for content-based hash matching!

5. **Next Paths to Probe**: ONLY paths extracted from the actual response content.
   
6. **Confidence Assessment**: Rate as "high", "medium", or "low"
   - "high" requires: favicon + title_pattern + body_patterns (all three!)
   - "medium" if only 2 signal types
   - "low" if only 1 signal type

7. **Should Continue**: false if enough distinctive signals found (favicon + title + body) OR no new paths

Respond in JSON format:
{{
    "app_name": "Identified Name (without version/year unless include_version=true)",
    "app_version": "version if detected (for reference only)",
    "confidence_level": "high|medium|low",
    "confidence_reasoning": "Explain confidence based on mode-appropriate signals",
    "page_signatures": [
        {{
            "path": "/",
            "title_pattern": "App Name only (e.g., 'Hackazon', NOT 'Bootstrap')",
            "body_patterns": ["App Name", "One unique string"]
        }}
    ],
    "discovered_endpoints": [
        {{"path": "/actual/path", "reason": "What this does", "priority": "high"}}
    ],
    "discovered_assets": [
        {{"type": "favicon", "path": "/assets/favicon.ico", "reason": "Favicon for hashing"}},
        {{"type": "logo", "path": "/images/AppName.png", "reason": "Logo contains app name"}}
    ],
    "next_paths_to_probe": ["/extracted/from/links"],
    "next_paths_reasoning": "Where these paths were found",
    "should_continue": true,
    "should_continue_reasoning": "Why continue or stop"
}}

⚠️ LIMITS: Max 2 page_signatures, max 2 body_patterns per page. Quality over quantity!"""


def get_normalization_prompt(
    mode: str,
    include_version: bool,
    base_url: str,
    summary: str
) -> str:
    """Generate the fingerprint normalization prompt."""
    
    mode_rules = get_mode_rules(mode)
    version_rules = get_version_rules(include_version)
    
    return f"""You are finalizing a web fingerprint. Review all discovered information and create a normalized fingerprint.

**Discovery Summary:**
{summary}

{mode_rules}

{version_rules}

**CRITICAL RULES FOR FINGERPRINTING:**

⚠️ IMPORTANT: Quality over quantity! We want 1-2 HIGHLY UNIQUE patterns, not many generic ones.
Each pattern will generate a Shodan/Censys query that costs API tokens - generic patterns waste tokens!

1. **Page Signatures (LIMIT TO 2 MAXIMUM)** - Only the most distinctive:
   ✓ title_pattern: MUST contain the APPLICATION NAME (e.g., "Hackazon", "OWASP Juice Shop")
   ✓ body_patterns: ONLY 1-2 patterns containing the APPLICATION NAME or truly unique identifiers
   ✓ Keep it minimal - we only use the FIRST 2 page signatures anyway!
   
   ✗ THESE PATTERNS ARE BLACKLISTED (match millions of sites, waste API tokens):
     - Framework names: "Bootstrap", "jQuery", "Font Awesome", "React", "Angular", "Vue"
     - Common UI text: "Login", "Logout", "Search", "Home", "Welcome", "Dashboard"
     - Social/common: "Twitter", "Facebook", "Google", "Copyright"
     - Generic CSS paths: "/css/bootstrap.css", "/font-awesome/"

2. **Distinctive Features** - Must be UNIQUE to this target:
   ✓ Name (app name OR company name depending on mode)
   ✓ Unique file paths with distinctive names
   ✓ Distinctive meta tags or specific titles
   ✗ Generic server signatures (Apache, nginx)
   ✗ Common headers (Content-Type, X-Powered-By)

3. **Body Patterns (MANDATORY - find at least 2):**
   Look for these in the HTML content:
   ✓ Application/company name mentions (e.g., "OWASP Juice Shop")
   ✓ Unique CSS/JS file paths containing app name (e.g., "/juice-shop/")
   ✓ Meta description or og:title with app name
   ✓ Distinctive error messages or UI text with app name
   ✓ Unique identifiers in paths (e.g., "/rest/products", "/api/Challenges")
   
   ✗ DO NOT include generic framework patterns:
     - Angular: ng-app, ng-controller, ng-model, app-root
     - React: data-reactroot, __next
     - Vue: v-app, v-model, __nuxt
     - Generic: bootstrap, jquery, polyfill, webpack
   ✗ DO NOT include generic HTML: viewport, charset, class="

4. **Title Patterns (MANDATORY if title exists):**
   ✓ Extract the EXACT title from "TITLE TAG:" in the content
   ✓ Use OR patterns for variations: "OWASP Juice Shop|Juice Shop"
   ✗ Generic titles: "Home", "Welcome", "Dashboard"

**OUTPUT REQUIREMENTS:**
- page_signatures: MAXIMUM 2 (we only use the first 2)
- title_pattern: MUST contain the APPLICATION NAME, not generic words
- body_patterns: MAXIMUM 2 per page, MUST be unique to this app (contain app name)
- Total queries generated = (title patterns × 2) + (body patterns × 2) → Keep minimal!

**REGEX PATTERN GUIDELINES:**
- title_pattern: "Term1|Term2|Term3" (OR pattern for alternatives)
- body_patterns: Simple strings like ["OWASP Juice Shop", "juice-shop"] - NOT regex, just keywords

Respond in JSON format:
{{
    "app_name": "Name (without version/year unless include_version=true)",
    "confidence_level": "high|medium|low",
    "distinctive_features": [
        "Feature that uniquely identifies this target"
    ],
    "page_signatures": [
        {{
            "url": "/",
            "title_pattern": "KeyTerm1|KeyTerm2 (regex with OR)",
            "body_patterns": [
                "SimpleKeyword1",
                "SimpleKeyword2"
            ]
        }}
    ],
    "notes": "Explanation of uniqueness and confidence"
}}"""


def get_github_analysis_prompt(
    mode: str,
    include_version: bool,
    context: str
) -> str:
    """Generate the GitHub repo analysis prompt."""
    
    mode_rules = get_mode_rules(mode)
    version_rules = get_version_rules(include_version)
    
    return f"""You are a web application fingerprinting expert analyzing a GitHub repository to extract unique identification signals.

**Repository Analysis:**
{context}

{mode_rules}

{version_rules}

**YOUR TASK:**
Analyze this repository and identify patterns that will be VISIBLE IN HTTP RESPONSES when the app is deployed.

1. **Identity**: What is this? (Application name OR Organization name based on mode)

2. **Distinctive Features** - Must be VISIBLE in HTTP responses to scanners:
   ✓ URL paths accessible via HTTP (e.g., "/vulnerabilities/", "/dvwa/")
   ✓ HTML content visible in page source
   ✓ CSS/JS file paths referenced in HTML (e.g., "/dvwa/css/main.css")
   ✓ Unique text in page titles or body
   ✓ Image/favicon URLs
   ✗ DO NOT include: PHP function names (not in HTTP response)
   ✗ DO NOT include: Composer/npm dependencies (not in HTTP response)
   ✗ DO NOT include: Internal variable names (not in HTTP response)
   ✗ DO NOT include: Code comments (not in HTTP response)

3. **Page Signatures** - CRITICAL: Extract ONLY from actual source code!
   - **title_pattern**: Extract EXACT text from <title> tags in the source code
     - Look for: <title>...</title> patterns in HTML/PHP/template files
     - If title is dynamic like {{{{$var}}}}, use the static parts around it
     - Example: "<title>Login :: Damn Vulnerable Web Application (DVWA)</title>" → "Damn Vulnerable Web Application|DVWA"
     - DO NOT invent or guess titles - only use what you SEE in the code
   - **body_patterns**: Extract EXACT strings that appear in the source code
     - Look for unique text in HTML templates
     - DO NOT hallucinate or infer patterns

4. **Unique Endpoints**: Identify paths that would exist in a deployed instance:
   - Only paths that appear to be web-accessible
   - Include expected HTTP status and content patterns

5. **Confidence Level**:
   - high = favicon + title_pattern + body_patterns (all three!)
   - medium = 2 out of 3 signal types
   - low = only 1 signal type

**CRITICAL RULES - MULTI-SIGNAL FINGERPRINTING:**
⚠️ A fingerprint with ONLY a favicon is WEAK! You MUST provide:
- favicon (from static assets)
- title_pattern (from <title> tags in the code)
- body_patterns (2-5 distinctive strings from templates/HTML)

For title_pattern:
- Extract from actual <title> tags you see in the provided code
- If dynamic like "{{{{$var}}}}", look for static parts or rely on body_patterns
- DO NOT hallucinate - only use what you SEE

For body_patterns (MANDATORY - find at least 2):
- Application name mentions in HTML/templates
- Unique CSS class names containing app name
- Distinctive text in templates
- Meta description or og:title content
- Unique error messages or UI text

**EXAMPLES:**
- If you see: <title>Login :: Damn Vulnerable Web Application (DVWA)</title>
  → title_pattern: "Damn Vulnerable Web Application|DVWA"
- If you see: <title>{{{{$pPage['title']}}}}</title> (fully dynamic)
  → Skip title_pattern, rely on body_patterns instead
- If you see: "Welcome to DVWA" in HTML body
  → body_pattern: "Welcome to DVWA"

Respond in JSON format:
{{
    "app_name": "Name (without version/year unless include_version=true)",
    "app_version_pattern": "Optional version regex if detectable",
    "confidence_level": "high|medium|low",
    "confidence_reasoning": "Why this confidence level",
    "distinctive_features": [
        "URL path /vulnerabilities/ visible in deployed app",
        "CSS file /dvwa/css/main.css referenced in HTML",
        "Favicon at /favicon.ico with unique hash"
    ],
    "page_signatures": [
        {{
            "url": "/",
            "title_pattern": "ONLY patterns extracted from actual <title> tags (or null if dynamic)",
            "body_patterns": [
                "Exact string from HTML templates"
            ]
        }}
    ],
    "notes": "Additional observations about fingerprinting this target"
}}"""

