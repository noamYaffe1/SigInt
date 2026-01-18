# Discovery Plugins

This directory contains discovery plugins for SigInt. Each plugin integrates with a different search engine/API to find hosts matching fingerprint patterns.

## Available Plugins

| Plugin | Description | Required Environment Variables |
|--------|-------------|-------------------------------|
| `shodan` | Shodan search engine | `SHODAN_API_KEY` |
| `censys` | Censys Platform API | `CENSYS_PERSONAL_ACCESS_TOKEN`, `CENSYS_ORG_ID` (optional) |

## Creating a New Plugin

### Quick Start

1. **Copy the template:**
   ```bash
   cp plugins/discovery/_template.py plugins/discovery/myservice_plugin.py
   ```

2. **Edit the new file:**
   - Rename the class from `TemplatePlugin` to `MyServicePlugin`
   - Update class attributes (`name`, `description`, `supported_query_types`)
   - Implement the required methods

3. **Add credentials to `.env`:**
   ```bash
   # Add to .env file
   MYSERVICE_API_KEY=your-api-key-here
   ```

4. **Register the plugin** (uncomment the last line in your plugin file):
   ```python
   PluginRegistry.register(MyServicePlugin)
   ```

5. **Test your plugin:**
   ```bash
   python main.py discover --list-plugins
   ```

### Plugin Structure

Every plugin must inherit from `DiscoveryPlugin` and implement these:

```python
from plugins.discovery import (
    DiscoveryPlugin,
    DiscoveryQuery,
    DiscoveryResult,
    NormalizedHost,
    QueryType,
    PluginRegistry,
)

class MyServicePlugin(DiscoveryPlugin):
    # Class attributes (required)
    name = "myservice"                    # Unique identifier (lowercase)
    description = "My search service"     # Human-readable description
    requires_auth = True                  # Does it need API key?
    supported_query_types = [             # What queries can it handle?
        QueryType.FAVICON_HASH,
        QueryType.TITLE_PATTERN,
        QueryType.BODY_PATTERN,
    ]
    
    def __init__(self, api_key: str = None):
        """Load credentials from args or environment."""
        self.api_key = api_key or os.environ.get("MYSERVICE_API_KEY")
    
    def is_configured(self) -> bool:
        """Return True if plugin has valid credentials."""
        return bool(self.api_key)
    
    def translate_query(self, query: DiscoveryQuery) -> str:
        """Convert generic query to service-specific syntax."""
        # Example: QueryType.TITLE_PATTERN -> 'title:"value"'
        pass
    
    def search(self, query: DiscoveryQuery, max_results: int = None) -> DiscoveryResult:
        """Execute search and return normalized results."""
        pass
```

### Required Methods

#### `__init__(self, **kwargs)`

Initialize the plugin with credentials. Always support loading from environment variables:

```python
def __init__(self, api_key: str = None, api_secret: str = None):
    self.api_key = api_key or os.environ.get("MYSERVICE_API_KEY")
    self.api_secret = api_secret or os.environ.get("MYSERVICE_API_SECRET")
```

#### `is_configured(self) -> bool`

Check if the plugin has all required credentials:

```python
def is_configured(self) -> bool:
    return bool(self.api_key and self.api_secret)
```

#### `translate_query(self, query: DiscoveryQuery) -> str`

Convert a `DiscoveryQuery` to your service's native query syntax:

```python
def translate_query(self, query: DiscoveryQuery) -> str:
    if query.raw_query:
        return query.raw_query  # Use raw query if provided
    
    translations = {
        QueryType.FAVICON_HASH: lambda v: f'icon_hash:{v}',
        QueryType.TITLE_PATTERN: lambda v: f'title:"{v}"',
        QueryType.BODY_PATTERN: lambda v: f'body:"{v}"',
        QueryType.HEADER_PATTERN: lambda v: f'header:"{v}"',
    }
    
    translator = translations.get(query.query_type)
    return translator(query.value) if translator else query.value
```

#### `search(self, query: DiscoveryQuery, max_results: int = None) -> DiscoveryResult`

Execute the search and return results:

```python
def search(self, query: DiscoveryQuery, max_results: int = None) -> DiscoveryResult:
    if not self.is_configured():
        return DiscoveryResult(query=query, error="Not configured")
    
    native_query = self.translate_query(query)
    hosts = []
    
    try:
        # Make API call
        response = requests.get(
            "https://api.myservice.com/search",
            params={"query": native_query},
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        response.raise_for_status()
        data = response.json()
        
        # Normalize results
        for item in data.get("results", []):
            host = self._normalize_result(item)
            if host:
                hosts.append(host)
        
        return DiscoveryResult(
            query=query,
            hosts=hosts,
            total_available=data.get("total", len(hosts))
        )
    except Exception as e:
        return DiscoveryResult(query=query, hosts=hosts, error=str(e))
```

### Normalizing Results

All plugins must convert their API responses to `NormalizedHost` format:

```python
def _normalize_result(self, result: dict) -> Optional[NormalizedHost]:
    try:
        ip = result.get("ip")
        port = result.get("port", 80)
        
        if not ip:
            return None
        
        # Filter out None values from location
        location = {}
        if result.get("country"):
            location["country"] = result["country"]
        if result.get("city"):
            location["city"] = result["city"]
        
        return NormalizedHost(
            ip=ip,
            port=port,
            protocol="https" if port == 443 else "http",
            hostname=result.get("hostname"),
            source=self.name,  # Plugin name as source
            last_seen=result.get("last_seen"),
            location=location if location else None,
            metadata={
                "org": result.get("organization"),
                "asn": result.get("asn"),
            }
        )
    except Exception:
        return None
```

### Query Types

Plugins can support these query types:

| QueryType | Description | Example Value |
|-----------|-------------|---------------|
| `FAVICON_HASH` | MMH3 hash of favicon | `-231109625` |
| `IMAGE_HASH` | MD5/MMH3 hash of image | `d41d8cd98f00b204...` |
| `TITLE_PATTERN` | HTML `<title>` content | `Admin Panel` |
| `BODY_PATTERN` | HTML body content | `Powered by WordPress` |
| `HEADER_PATTERN` | HTTP header value | `X-Powered-By: PHP` |
| `CUSTOM` | Raw query in native syntax | (service-specific) |

Only add query types to `supported_query_types` that your service actually supports.

### Rate Limiting

If your service has rate limits, implement them in the plugin:

```python
import threading
import time

class MyServicePlugin(DiscoveryPlugin):
    _rate_limit_lock = threading.Lock()
    _last_request_time = 0
    _min_request_interval = 1.0  # 1 second between requests
    
    @classmethod
    def _enforce_rate_limit(cls):
        with cls._rate_limit_lock:
            elapsed = time.time() - cls._last_request_time
            if elapsed < cls._min_request_interval:
                time.sleep(cls._min_request_interval - elapsed)
            cls._last_request_time = time.time()
    
    def search(self, query, max_results=None):
        self._enforce_rate_limit()
        # ... rest of search implementation
```

### Debug Logging

Add debug logging for troubleshooting:

```python
import logging
from core.debug import debug_print

logger = logging.getLogger("sigint.myservice")

class MyServicePlugin(DiscoveryPlugin):
    def search(self, query, max_results=None):
        native_query = self.translate_query(query)
        
        # Debug logging
        logger.debug(f"[MYSERVICE] Query: {native_query}")
        debug_print(f"[MYSERVICE DEBUG] Query: {native_query}")
        
        # ... make API call
```

Enable debug output with `--verbose` flag or `SIGINT_DEBUG=1`.

### Registration

The plugin is auto-discovered when you uncomment the registration line:

```python
# At the bottom of your plugin file:
PluginRegistry.register(MyServicePlugin)
```

### Testing Your Plugin

1. **Check registration:**
   ```bash
   python main.py discover --list-plugins
   ```

2. **Test with a fingerprint:**
   ```bash
   python main.py discover output/fingerprints/my_app.json --plugins myservice
   ```

3. **Enable debug mode for troubleshooting:**
   ```bash
   SIGINT_DEBUG=1 python main.py discover output/fingerprints/my_app.json --plugins myservice
   ```

## File Structure

```
plugins/discovery/
├── __init__.py         # Exports plugin classes and types
├── base.py             # Base classes (DiscoveryPlugin, QueryType, etc.)
├── registry.py         # PluginRegistry for auto-discovery
├── _template.py        # Template for new plugins (copy this!)
├── shodan_plugin.py    # Shodan implementation
├── censys_plugin.py    # Censys implementation
└── README.md           # This file
```

## Environment Variables

Add your plugin's credentials to the `.env` file in the project root:

```bash
# .env file

# Shodan
SHODAN_API_KEY=your-shodan-api-key

# Censys
CENSYS_PERSONAL_ACCESS_TOKEN=your-censys-token
CENSYS_ORG_ID=optional-org-id

# Your new plugin
MYSERVICE_API_KEY=your-api-key
MYSERVICE_API_SECRET=your-api-secret
```

See `.env.example` for all available options.

