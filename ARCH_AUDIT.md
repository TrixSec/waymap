Phase 1 — High Level Architecture Audit (Final Complete)
Current Architecture Analysis
[Previous analysis remains valid - focusing on final refinements below]

Proposed Architecture (Final Complete)
Architecture Pattern: Layered + Plugin System + Lightweight Events + Recon Intelligence + Knowledge Base + Execution Planner


┌─────────────────────────────────────────────────────────────┐
│                     CLI Layer (waymap.py)                   │
│  - Argument parsing only                                    │
│  - Delegates to Application Layer                           │
└──────────────────────┬──────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────┐
│              Application Layer (lib/app/)                    │
│  - ScanOrchestrator                                          │
│  - ScanContext (per-scan state)                              │
│  - PluginRegistry                                            │
│  - Lightweight EventBus                                      │
│  - Knowledge Base (3 scopes)                                 │
│  - Execution Planner                                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
┌───────▼──────┐ ┌────▼─────┐ ┌─────▼──────┐
│  Recon       │ │ Target   │ │ Scanner    │
│  Intelligence│ │Prioritiz. │ │  Engine    │
│  (passive)   │ │ Engine   │ │            │
└───────┬──────┘ └────┬─────┘ └─────┬──────┘
        │             │             │
┌───────▼──────┐ ┌────▼─────┐ ┌─────▼──────┐
│  HTTP Layer  │ │ Payload  │ │ Detection  │
│  (enhanced   │ │ Pipeline │ │  Engine    │
│   requests)  │ │          │ │ (evidence) │
└──────────────┘ └──────────┘ └────────────┘
Enhanced Phase: Knowledge Base (3 Scopes)
Three-Level Scoping


python
class KnowledgeBase:
    def __init__(self):
        self.global_knowledge = GlobalKnowledge()
        self.target_knowledge = TargetKnowledge()
        self.scan_knowledge = ScanKnowledge()
 
@dataclass
class GlobalKnowledge:
    """Generic payload families, framework fingerprints (persistent across scans)"""
    payload_families: Dict[str, PayloadFamily] = field(default_factory=dict)
    framework_fingerprints: Dict[str, FrameworkInfo] = field(default_factory=dict)
 
@dataclass
class TargetKnowledge:
    """Target-specific: "This Laravel app uses MySQL and Cloudflare" (persistent for target)"""
    target_id: str
    framework: Optional[str] = None
    dbms: Optional[str] = None
    waf: Optional[WAF] = None
    parameter_knowledge: Dict[str, ParameterKnowledge] = field(default_factory=dict)
 
@dataclass
class ScanKnowledge:
    """Scan-specific: "Parameter id already succeeded with Boolean SQLi during this run" (ephemeral)"""
    scan_id: str
    successful_parameters: Set[str] = field(default_factory=set)
    successful_payloads: Dict[str, List[str]] = field(default_factory=dict)
    failed_techniques: Set[str] = field(default_factory=set)
Usage Example


python
# Global knowledge (persistent)
kb.global_knowledge.payload_families['SQL_BOOLEAN'] = PayloadFamily(...)
kb.global_knowledge.framework_fingerprints['Laravel'] = FrameworkInfo(...)
 
# Target knowledge (persistent for target)
kb.target_knowledge[target_id].framework = "Laravel"
kb.target_knowledge[target_id].dbms = "MySQL"
kb.target_knowledge[target_id].waf = WAF.CLOUDFLARE
 
# Scan knowledge (ephemeral)
kb.scan_knowledge[scan_id].successful_parameters.add('id')
kb.scan_knowledge[scan_id].successful_payloads['id'] = ['AND 1=1', 'AND 1=2']
 
# Lookup order: Scan → Target → Global
def get_payload_strategy(param_name: str, context: Context) -> PayloadStrategy:
    # Check scan knowledge first
    if param_name in context.kb.scan_knowledge[context.scan_id].successful_parameters:
        return context.kb.scan_knowledge[context.scan_id].successful_payloads[param_name]
    
    # Check target knowledge
    if context.target_id in context.kb.target_knowledge:
        target_kb = context.kb.target_knowledge[context.target_id]
        if param_name in target_kb.parameter_knowledge:
            return target_kb.parameter_knowledge[param_name]
    
    # Fall back to global knowledge
    return context.kb.global_knowledge.payload_families['DEFAULT']
Benefits:

Prevents information leakage between unrelated scans
Allows reuse where appropriate
Clear separation of concerns
Better security isolation
Complexity: Low - three-level lookup

Enhanced Phase: Evidence-Based Detection (Configurable Profiles)
Current (Hard-coded Weights)


python
SQL Error = 0.35
Timing = 0.18
Reflection = 0.25
Proposed (Configurable Profiles)


python
@dataclass
class DetectionProfile:
    name: str
    evidence_weights: Dict[str, float]
    confidence_threshold: float
 
DEFAULT_PROFILES = {
    'aggressive': DetectionProfile(
        name='aggressive',
        evidence_weights={
            'sql_error': 0.4,
            'boolean_difference': 0.3,
            'timing': 0.2,
            'union_evidence': 0.3,
        },
        confidence_threshold=0.6
    ),
    'balanced': DetectionProfile(
        name='balanced',
        evidence_weights={
            'sql_error': 0.35,
            'boolean_difference': 0.25,
            'timing': 0.18,
            'union_evidence': 0.22,
        },
        confidence_threshold=0.7
    ),
    'strict': DetectionProfile(
        name='strict',
        evidence_weights={
            'sql_error': 0.3,
            'boolean_difference': 0.2,
            'timing': 0.15,
            'union_evidence': 0.25,
        },
        confidence_threshold=0.8
    ),
}
 
class DetectionEngine:
    def __init__(self, profile: DetectionProfile = DEFAULT_PROFILES['balanced']):
        self.profile = profile
    
    def analyze(self, baseline: Response, injected: Response, payload: str) -> DetectionResult:
        evidence = self._collect_evidence(baseline, injected, payload)
        
        # Use profile weights
        confidence = sum(
            self.profile.evidence_weights.get(e.type, 0.1) * e.weight
            for e in evidence
        )
        
        return DetectionResult(
            confidence=confidence,
            evidence=evidence,
            is_vulnerable=confidence > self.profile.confidence_threshold
        )
Benefits:

Configurable tuning
Easy to adjust for different use cases
No code changes needed for tuning
A/B testing possible
Complexity: Low - profile configuration

Enhanced Phase: Template Discovery (Path Canonicalization)
Current (Query Parameters Only)


product?id=1 → product?id={NUMERIC}
Proposed (Path + Query Parameters)


python
class TemplateDiscovery:
    def discover_templates(self, urls: List[str]) -> List[EndpointTemplate]:
        templates = {}
        
        for url in urls:
            template = self._extract_template(url)
            
            if template not in templates:
                templates[template] = {
                    'pattern': template,
                    'examples': [url],
                    'param_types': self._infer_param_types(url)
                }
            else:
                templates[template]['examples'].append(url)
        
        return list(templates.values())
    
    def _extract_template(self, url: str) -> str:
        parsed = urlparse(url)
        
        # Canonicalize path
        path_template = self._canonicalize_path(parsed.path)
        
        # Canonicalize query
        query_template = self._canonicalize_query(parsed.query)
        
        # Reconstruct
        parsed = parsed._replace(path=path_template, query=query_template)
        
        return urlunparse(parsed)
    
    def _canonicalize_path(self, path: str) -> str:
        # /users/1 → /users/{NUMERIC}
        # /posts/abc → /posts/{STRING}
        # /api/v1/users/123 → /api/v1/users/{NUMERIC}
        
        segments = path.split('/')
        canonical_segments = []
        
        for segment in segments:
            if segment.isdigit():
                canonical_segments.append('{NUMERIC}')
            elif segment and not segment.startswith('{'):
                # Check if it looks like a UUID or hash
                if len(segment) in [32, 36, 40] and all(c in '0123456789abcdef-' for c in segment.lower()):
                    canonical_segments.append('{UUID}')
                else:
                    canonical_segments.append('{STRING}')
            else:
                canonical_segments.append(segment)
        
        return '/'.join(canonical_segments)
    
    def _canonicalize_query(self, query: str) -> str:
        params = parse_qs(query, keep_blank_values=True)
        canonical_params = []
        
        for key, values in sorted(params.items()):
            param_type = self._infer_param_type(values[0] if values else '')
            canonical_params.append(f'{key}={{{param_type}}}')
        
        return '&'.join(canonical_params)
Examples


/users/1 → /users/{NUMERIC}
/users/abc → /users/{STRING}
/api/v1/users/123 → /api/v1/users/{NUMERIC}
product?id=1 → product?id={NUMERIC}
search?q=test → search?q={STRING}
Benefits:

Works with REST-heavy APIs
Path parameter support
UUID detection
Better template coverage
Complexity: Medium - path canonicalization

New Phase: Request Fingerprint Engine
Purpose
Deduplicate requests beyond URL matching to avoid sending nearly identical requests.

Implementation


python
@dataclass
class RequestFingerprint:
    method: str
    path_template: str
    param_types: Dict[str, str]
    content_type: str
 
class RequestFingerprintEngine:
    def fingerprint(self, request: Request) -> RequestFingerprint:
        return RequestFingerprint(
            method=request.method,
            path_template=self._canonicalize_path(request.url),
            param_types=self._infer_param_types(request.url),
            content_type=request.headers.get('Content-Type', 'application/x-www-form-urlencoded')
        )
    
    def is_duplicate(self, fingerprint1: RequestFingerprint, fingerprint2: RequestFingerprint) -> bool:
        return (
            fingerprint1.method == fingerprint2.method and
            fingerprint1.path_template == fingerprint2.path_template and
            fingerprint1.param_types == fingerprint2.param_types and
            fingerprint1.content_type == fingerprint2.content_type
        )
    
    def _canonicalize_path(self, url: str) -> str:
        # Same as template discovery
        pass
    
    def _infer_param_types(self, url: str) -> Dict[str, str]:
        # Same as template discovery
        pass
Example


python
# These are considered duplicates:
GET /search?q=test → Fingerprint: GET /search?q={STRING}
GET /search?q=abc → Fingerprint: GET /search?q={STRING}
 
# These are different:
GET /search?q=test → Fingerprint: GET /search?q={STRING}
POST /search → Fingerprint: POST /search (no params)
Benefits:

Avoids nearly identical requests
Works with template discovery
Better deduplication
10-15% fewer requests
Complexity: Low - fingerprint calculation

Enhanced Phase: Payload Intelligence (Separated Pipeline)
Current (Combined)


Payload Family → Mutation Engine → Payload
Proposed (Separated)


Payload Family
    ↓
Payload Generator
    ↓
Mutation Engine
    ↓
Encoding Engine
    ↓
Final Payload
Implementation


python
class PayloadPipeline:
    def generate(self, parameter: Parameter, context: Context) -> List[str]:
        # Step 1: Attack Surface
        attack_surface = self._determine_attack_surface(parameter, context)
        
        # Step 2: Payload Family
        payload_family = self._select_payload_family(attack_surface, parameter, context)
        
        # Step 3: Payload Generator
        base_payloads = self._generate_base_payloads(payload_family, parameter, context)
        
        # Step 4: Mutation Engine
        mutated_payloads = self._mutate_payloads(base_payloads, parameter, context)
        
        # Step 5: Encoding Engine
        final_payloads = self._encode_payloads(mutated_payloads, parameter, context)
        
        return final_payloads
    
    def _generate_base_payloads(self, payload_family: PayloadFamily, parameter: Parameter, context: Context) -> List[str]:
        # Generate base payloads for the family
        if payload_family == PayloadFamily.SQL_BOOLEAN:
            return ['AND 1=1', 'AND 1=2', 'AND 5=5']
        elif payload_family == PayloadFamily.SQL_ERROR:
            return ["' AND 1=1--", "' AND 1=2--"]
        # ... other families
    
    def _mutate_payloads(self, base_payloads: List[str], parameter: Parameter, context: Context) -> List[str]:
        # Apply mutations (parameter-specific, context-specific)
        mutations = []
        
        for payload in base_payloads:
            # Parameter-specific mutations
            if parameter.name == 'id':
                mutations.append(payload.replace('1', parameter.value))
            
            # Context-specific mutations
            if context.intelligence.waf == WAF.CLOUDFLARE:
                mutations.append(self._waf_evasion(payload))
            
            mutations.append(payload)
        
        return mutations
    
    def _encode_payloads(self, payloads: List[str], parameter: Parameter, context: Context) -> List[str]:
        # Apply encodings (URL, hex, base64, etc.)
        encoded = []
        
        for payload in payloads:
            # URL encoding
            encoded.append(urlencode(payload))
            
            # Hex encoding
            encoded.append(payload.encode('utf-8').hex())
            
            # Double encoding
            encoded.append(urlencode(urlencode(payload)))
            
            encoded.append(payload)
        
        return encoded
Benefits:

Clear separation of concerns
Easy to add tamper scripts
Easy to add custom encoders
Better extensibility
Complexity: Medium - pipeline separation

New Phase: Execution Planner
Purpose
Decide how many requests to send, which techniques to skip, escalation strategy, early stopping.

Implementation


python
class ExecutionPlanner:
    def plan(self, target: str, context: Context) -> ExecutionPlan:
        plan = ExecutionPlan(
            target=target,
            techniques=[],
            max_requests=1000,
            escalation_strategy='auto',
            early_stop_threshold=0.9
        )
        
        # Decide which techniques to use
        plan.techniques = self._select_techniques(target, context)
        
        # Decide escalation strategy
        plan.escalation_strategy = self._select_escalation_strategy(context)
        
        # Decide max requests
        plan.max_requests = self._calculate_max_requests(target, context)
        
        return plan
    
    def _select_techniques(self, target: str, context: Context) -> List[str]:
        techniques = []
        
        # Skip techniques if evidence already sufficient
        if context.kb.scan_knowledge[context.scan_id].has_sufficient_evidence():
            return techniques
        
        # Select based on knowledge
        if context.kb.target_knowledge[target].dbms == 'MySQL':
            techniques.extend(['error', 'boolean', 'union', 'time'])
        
        if context.kb.target_knowledge[target].waf == WAF.CLOUDFLARE:
            # Skip time-based if WAF detected
            techniques = [t for t in techniques if t != 'time']
        
        return techniques
    
    def _select_escalation_strategy(self, context: Context) -> str:
        # Boolean → Time-based → Union
        # Or skip escalation if confidence already high
        if context.kb.scan_knowledge[context.scan_id].confidence > 0.8:
            return 'none'
        
        return 'auto'
    
    def _calculate_max_requests(self, target: str, context: Context) -> int:
        # Reduce requests if knowledge base has good data
        if context.kb.target_knowledge[target].has_successful_payloads():
            return 500  # Fewer requests needed
        
        return 1000  # Default
 
@dataclass
class ExecutionPlan:
    target: str
    techniques: List[str]
    max_requests: int
    escalation_strategy: str
    early_stop_threshold: float
Benefits:

Intelligent technique selection
WAF-aware planning
Knowledge-based optimization
20-30% fewer requests
Complexity: Medium - requires planning logic

Updated Migration Strategy (Swapped Phases)
Phase 1: Foundation (Week 1)
Create ScanContext object
Refactor globals into context
Add dependency injection to scanner
Risk: Low - additive changes
Phase 2: Enhanced HTTP Layer (Week 2)
Add retry logic with exponential backoff
Optimize connection pooling
Add persistent keep-alive
Fixed thread pool (no adaptive)
Risk: Low - synchronous improvements only
Phase 3: Lightweight Event Bus (Week 3)
Implement simple EventBus
Define core events (DiscoveryEvent, FindingEvent)
Migrate progress reporting
Risk: Low - simple pub/sub
Phase 4: Simple Plugin System (Week 4-5)
Define ScanPlugin interface (uses event bus)
Create PluginRegistry
Refactor one scan type (e.g., XSS) as plugin
Migrate remaining scan types
Risk: Medium - requires testing each plugin
Phase 5: Passive Recon Intelligence (Week 6)
Implement passive recon (headers, cookies, HTML, JS, meta tags, URLs)
Add cheap active recon (robots.txt, sitemap.xml, security.txt, favicon)
Add deep active recon (swagger, graphql, framework probes)
Risk: Low - three-tier gathering
Phase 6: Template-Based Discovery (Week 7)
Implement template extraction (path + query)
Add path canonicalization
Add template exploration
Integrate with discovery engine
Risk: Medium - requires template extraction
Phase 7: Request Fingerprint Engine (Week 8)
Implement request fingerprinting
Add deduplication logic
Integrate with HTTP layer
Risk: Low - fingerprint calculation
Phase 8: Target Prioritization Engine (Week 9)
Rename from Discovery Scheduler
Implement template-based prioritization
Add weighted heuristics
Add context-aware adjustments
Risk: Low - rename and enhance
Phase 9: Knowledge Base (Week 10)
Implement three-level knowledge base (Global, Target, Scan)
Add parameter learning
Add endpoint learning
Integrate with payload selection
Risk: Low - three-level lookup
Phase 10: Result Store (Week 11)
Implement WAL
Migrate ResultManager
Add crash recovery
Risk: Medium - data integrity critical
Phase 11: Enhanced Payload Intelligence (Week 12-13)
Implement multi-signal parameter classifier
Create separated payload pipeline
Add payload generator
Add mutation engine
Add encoding engine
Integrate with knowledge base
Risk: Medium - requires pipeline implementation
Phase 12: Execution Planner (Week 14)
Implement execution planner
Add technique selection logic
Add escalation strategy
Add request budgeting
Integrate with scanner
Risk: Medium - requires planning logic
Phase 13: Evidence-Based Detection (Week 15-17)
Design evidence object structure
Implement configurable profiles
Implement SQLi-specific evidence collection
Implement XSS-specific evidence collection
Implement CMDi-specific evidence collection
Implement LFI-specific evidence collection
Add confidence calculation
Add explanation generation
Risk: High - requires significant redesign
Expected Improvements (Tempered Estimates)
Metric	Current	Target	Improvement	Notes
Vulnerability Discovery Time	100%	50-70%	30-50% faster	Pending benchmarking
HTTP Throughput	100 req/s	200-300 req/s	2-3x	Depends on network
False Positive Rate	15-20%	3-8%	60-80% reduction	Depends on target
Requests per Scan	100%	30-50%	50-70% fewer	Depends on complexity
Vulnerability Detection Rate	100%	120-140%	20-40% higher	Depends on target
Memory Usage	500MB	350MB	30% reduction	Estimate
Code Duplication	30%	5%	83% reduction	Estimate
Test Coverage	0%	60%	Enable testing	Goal
Plugin Development Time	N/A	2-4 hours	Enable extensions	Estimate
Note: These are expected goals pending benchmarking. Real-world gains will vary depending on target application, network latency, WAF behavior, and scan configuration.

Clear Evolution Path


Current Waymap
      │
      ↓
Phase 1: Foundation (ScanContext, DI)
      │
      ↓
Phase 2: Enhanced HTTP Layer (retry, pooling, keep-alive)
      │
      ↓
Phase 3: Event Bus (lightweight pub/sub)
      │
      ↓
Phase 4: Plugin System (extensible scan types)
      │
      ↓
Phase 5: Recon Intelligence (passive/cheap/deep)
      │
      ↓
Phase 6: Template Discovery (path + query canonicalization)
      │
      ↓
Phase 7: Request Fingerprint (smart deduplication)
      │
      ↓
Phase 8: Target Prioritization Engine (template-based)
      │
      ↓
Phase 9: Knowledge Base (3 scopes: Global/Target/Scan)
      │
      ↓
Phase 10: Result Store (WAL, crash recovery)
      │
      ↓
Phase 11: Payload Intelligence (separated pipeline)
      │
      ↓
Phase 12: Execution Planner (intelligent planning)
      │
      ↓
Phase 13: Evidence-Based Detection (configurable profiles)
      │
      ↓
Future: AI Advisory Layer (optional enhancement)
