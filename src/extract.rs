use base64::Engine;
use regex::Regex;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyKind {
    Anthropic,
    OpenRouter,
    OpenAi,
    DashScope,
    /// Alibaba workspace credential (`sk-ws-…`). Kept separate from classic
    /// DashScope keys so quality scans can ignore workspace keys entirely.
    DashScopeWorkspace,
    Xai,
    Google,
    HuggingFace,
    FishAudio,
    ElevenLabs,
    Seedance,
    GithubPat,
    Generic,
}

impl KeyKind {
    pub fn label(self) -> &'static str {
        match self {
            KeyKind::Anthropic => "anthropic",
            KeyKind::OpenRouter => "openrouter",
            KeyKind::OpenAi => "openai",
            KeyKind::DashScope => "dashscope",
            KeyKind::DashScopeWorkspace => "dashscope_ws",
            KeyKind::Xai => "xai",
            KeyKind::Google => "google",
            KeyKind::HuggingFace => "huggingface",
            KeyKind::FishAudio => "fish_audio",
            KeyKind::ElevenLabs => "elevenlabs",
            KeyKind::Seedance => "seedance",
            KeyKind::GithubPat => "github_pat",
            KeyKind::Generic => "generic",
        }
    }

    pub fn default_endpoint(self) -> Option<&'static str> {
        match self {
            KeyKind::Anthropic => Some("https://api.anthropic.com"),
            KeyKind::OpenRouter => Some("https://openrouter.ai/api/v1"),
            KeyKind::OpenAi => Some("https://api.openai.com/v1"),
            KeyKind::DashScope => Some("https://dashscope.aliyuncs.com/compatible-mode/v1"),
            // Workspace keys only make sense with their ws-… endpoint; never
            // silently probe them against the public compatible endpoint.
            KeyKind::DashScopeWorkspace => None,
            KeyKind::Xai => Some("https://api.x.ai/v1"),
            KeyKind::HuggingFace => Some("https://router.huggingface.co/v1"),
            KeyKind::FishAudio => Some("https://api.fish.audio/v1"),
            KeyKind::ElevenLabs => Some("https://api.elevenlabs.io/v1"),
            KeyKind::Seedance => Some("https://ark.cn-beijing.volces.com/api/v3"),
            KeyKind::GithubPat => Some("https://api.github.com"),
            KeyKind::Google | KeyKind::Generic => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct EndpointHit {
    pub line: usize,
    pub url: String,
    pub strong: bool,
}

#[derive(Clone, Debug)]
pub struct KeyHit {
    pub line: usize,
    pub key: String,
    pub kind: KeyKind,
}

#[derive(Clone, Debug)]
pub struct PairHit {
    pub endpoint: String,
    pub key: String,
    pub kind: KeyKind,
    pub line: usize,
    pub distance: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Extraction {
    pub pairs: Vec<PairHit>,
    pub endpoints: Vec<EndpointHit>,
    pub keys: Vec<KeyHit>,
}

impl Extraction {
    pub fn strong_endpoints(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for e in &self.endpoints {
            if e.strong && seen.insert(e.url.clone()) {
                out.push(e.url.clone());
            }
        }
        out
    }
}

struct Patterns {
    assign: Regex,
    url: Regex,
    bare: Regex,
    keys: Vec<(KeyKind, Regex, usize)>,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        assign: Regex::new(
            r#"(?i)\b(?:base[_-]?url|api[_-]?(?:base|url|endpoint|host|domain)|openai[_-]?(?:base|url|api|endpoint)|anthropic[_-]?(?:base|url)|endpoint|server[_-]?url|proxy[_-]?url|api)\s*[:=]\s*["']?((?:https?://)?[a-z0-9][a-z0-9\-\.]*(?::\d{1,5})?(?:/[a-z0-9_\-\./%]*)?)"#,
        )
        .unwrap(),
        url: Regex::new(
            r#"(?i)\bhttps?://[a-z0-9][a-z0-9\-\.]*(?::\d{2,5})?(?:/[a-zA-Z0-9_\-\./%]*)?(?:\?[^\s"'<>\)\]]*)?"#,
        )
        .unwrap(),
        bare: Regex::new(
            r#"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+(?:com|in|io|ai|dev|xyz|top|cc|me|net|org|app|site|online|cloud|tech|pro|ru|cn|us|uk|de|fr|jp|sg|hk|co|so|sh|gg|tv|vip|fun|space|store|icu|buzz|live|wtf|one|link|world|zone|digital|agency|solutions|services|systems|network|host|website|press|news|blog|page)(?::\d{2,5})?(?:/v1)?\b"#,
        )
        .unwrap(),
        keys: vec![
            // GitHub PATs: these are credentials the bot itself can consume.
            (
                KeyKind::GithubPat,
                Regex::new(r"\bghp_[A-Za-z0-9]{36}\b").unwrap(),
                0,
            ),
            (
                KeyKind::GithubPat,
                Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{60,200}\b").unwrap(),
                0,
            ),
            (
                KeyKind::GithubPat,
                Regex::new(r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b").unwrap(),
                0,
            ),
            (
                KeyKind::GithubPat,
                Regex::new(r#"(?i)\b(?:GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|GH_PAT)\b\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,200})"#).unwrap(),
                1,
            ),
            // Classic `sk-<32hex>` is ambiguous (OpenAI relays share the shape):
            // it is relabelled to DashScope later only with DS context or a
            // nearby DashScope endpoint, so do not hard-tag it here.
            // ZhipuAI / Z.AI: 32 hex, dot, 10-30 alnum (id.secret).
            (
                KeyKind::Generic,
                Regex::new(r"\b[0-9a-f]{32}\.[A-Za-z0-9]{10,30}\b").unwrap(),
                0,
            ),
            // Moonshot / KIMI: sk- + exactly 48 alnum (51 chars total).
            (
                KeyKind::Generic,
                Regex::new(r"\bsk-[A-Za-z0-9]{48}\b").unwrap(),
                0,
            ),
            (
                KeyKind::Anthropic,
                Regex::new(r"\bsk-ant-[A-Za-z0-9_\-]{20,200}\b").unwrap(),
                0,
            ),
            (
                KeyKind::OpenRouter,
                Regex::new(r"\bsk-or-v1-[A-Za-z0-9_-]{32,200}\b").unwrap(),
                0,
            ),
            (
                KeyKind::DashScopeWorkspace,
                Regex::new(r"\bsk-ws-[A-Za-z0-9_.\-]{20,400}\b").unwrap(),
                0,
            ),
            (
                KeyKind::OpenAi,
                Regex::new(r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_\-]{20,200}\b").unwrap(),
                0,
            ),

            (
                KeyKind::Xai,
                Regex::new(r"\bxai-[A-Za-z0-9]{20,200}\b").unwrap(),
                0,
            ),
            (
                KeyKind::Google,
                Regex::new(r"\bAIza[0-9A-Za-z_\-]{35}\b").unwrap(),
                0,
            ),
            (
                KeyKind::HuggingFace,
                Regex::new(r"\bhf_[A-Za-z0-9]{20,200}\b").unwrap(),
                0,
            ),
            // Extra provider prefixes ported from the v11 Python parser
            // (key_patterns.py). Value: these shapes were the only way the
            // old parser caught non-OpenAI providers without environment
            // context.
            (KeyKind::Generic, Regex::new(r"\bnvapi-[A-Za-z0-9_-]{30,120}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\br8_[A-Za-z0-9]{37}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bfish_[0-9a-f]{64}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bpplx-[a-z0-9]{40,60}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bcsk-[A-Za-z0-9]{40,60}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bjina_[0-9a-f]{32}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bdiy-[A-Za-z0-9]{32,64}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bvultr-[A-Za-z0-9_-]{36}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bdop_v1_[0-9a-f]{64}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bsg-[A-Za-z0-9]{32}\b").unwrap(), 0),
            (KeyKind::Generic, Regex::new(r"\bmistral-[A-Za-z0-9]{20,40}\b").unwrap(), 0),
            // ── ported verbatim from key_patterns_v12_fleet.py (266 rules) ──
            (KeyKind::OpenAi, Regex::new(r##"\bsk-admin-[A-Za-z0-9_-]{58}T3BlbkFJ[A-Za-z0-9_-]{58}\b"##).unwrap(), 0), // OPENAI_ADMIN
            (KeyKind::Generic, Regex::new(r##"\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b"##).unwrap(), 0), // LANGSMITH
            (KeyKind::Generic, Regex::new(r##"\bdapi[a-f0-9]{32}(?:-\d)?\b"##).unwrap(), 0), // DATABRICKS
            (KeyKind::Generic, Regex::new(r##"\bdp\.pt\.[a-z0-9]{43}\b"##).unwrap(), 0), // DOPPLER
            (KeyKind::Generic, Regex::new(r##"\bAKCp[A-Za-z0-9]{69}\b"##).unwrap(), 0), // ARTIFACTORY
            (KeyKind::Generic, Regex::new(r##"\bLTAI[a-z0-9]{12,22}\b"##).unwrap(), 0), // ALIBABA_LTAI
            (KeyKind::Generic, Regex::new(r##"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b"##).unwrap(), 0), // AGE_KEY
            (KeyKind::Generic, Regex::new(r##"\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b"##).unwrap(), 0), // ONEPASSWORD
            (KeyKind::Generic, Regex::new(r##"\b[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34}\b"##).unwrap(), 0), // AZURE_AD
            (KeyKind::Generic, Regex::new(r##"\bHRKU-AA[0-9a-zA-Z_-]{58}"##).unwrap(), 0), // HEROKU
            (KeyKind::Generic, Regex::new(r##"\bsbp-[a-f0-9]{40}"##).unwrap(), 0), // SUPABASE
            (KeyKind::Generic, Regex::new(r##"[a-f0-9]{32}\.[A-Za-z0-9]{10,30}"##).unwrap(), 0), // ZAI
            (KeyKind::Generic, Regex::new(r##"fish_[a-f0-9]{64}"##).unwrap(), 0), // SAKANA
            // ── treg.to / agent-tool providers (eni 2026-11-03) ──
            (KeyKind::Generic, Regex::new(r#"fc-[A-Za-z0-9]{28,64}"#).unwrap(), 0), // FIRECRAWL
            (KeyKind::Generic, Regex::new(r#"tvly-[A-Za-z0-9_-]{20,80}"#).unwrap(), 0), // TAVILY
            (KeyKind::Generic, Regex::new(r#"apify_api_[A-Za-z0-9]{20,64}"#).unwrap(), 0), // APIFY
            (KeyKind::Generic, Regex::new(r#"trg_live_[A-Za-z0-9]{20,80}"#).unwrap(), 0), // TREG.TO
            (KeyKind::OpenRouter, Regex::new(r##"sk-or-v1-[0-9a-f]{48,70}"##).unwrap(), 0), // OPENROUTER
            (KeyKind::DashScope, Regex::new(r##"sk-sp-[A-Za-z0-9_\-]{20,64}|sk-ws-[A-Za-z0-9_\-\.]{16,200}|sk-[a-f0-9]{32}"##).unwrap(), 0), // DASHSCOPE
            (KeyKind::Generic, Regex::new(r##"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}"##).unwrap(), 0), // MINIMAX
            (KeyKind::Generic, Regex::new(r##"sk-[a-f0-9]{32}"##).unwrap(), 0), // DEEPSEEK
            (KeyKind::Generic, Regex::new(r##"sk-[a-zA-Z0-9]{48}"##).unwrap(), 0), // SILICONFLOW
            (KeyKind::Generic, Regex::new(r##"sk-[A-Za-z0-9]{48}"##).unwrap(), 0), // KIMI
            (KeyKind::Generic, Regex::new(r##"\b[0-9a-f]{32}:[0-9a-f]{64}\b"##).unwrap(), 0), // FAL
            (KeyKind::Generic, Regex::new(r##"(?:ARK|VOLCENGINE|DOUBAO|SEEDANCE|BYTEDANCE)_?API_KEY["\']?\s*[=:]\s*["\']?([A-Za-z0-9\-]{20,64})"##).unwrap(), 1), // ARK
            (KeyKind::Generic, Regex::new(r##"(?:fireworks|FIREWORKS)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{48,52})"##).unwrap(), 1), // FIREWORKS
            (KeyKind::Generic, Regex::new(r##"fw_[A-Za-z0-9]{40,60}"##).unwrap(), 0), // FIREWORKS
            (KeyKind::Generic, Regex::new(r##"gsk_[A-Za-z0-9]{40,60}"##).unwrap(), 0), // GROQ
            (KeyKind::Generic, Regex::new(r##"(?:cohere|COHERE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{40})"##).unwrap(), 1), // COHERE
            (KeyKind::Generic, Regex::new(r##"(?:novita|NOVITA)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{32,40})"##).unwrap(), 1), // NOVITA
            (KeyKind::Generic, Regex::new(r##"pplx-[a-z0-9]{56}"##).unwrap(), 0), // PERPLEXITY
            (KeyKind::ElevenLabs, Regex::new(r##"\b(?:elevenlabs|ELEVENLABS|xi)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})"##).unwrap(), 1), // ELEVENLABS
            (KeyKind::Generic, Regex::new(r##"sk-[A-Za-z0-9]{99}"##).unwrap(), 0), // STABILITY
            (KeyKind::Generic, Regex::new(r##"\bnvapi-[A-Za-z0-9_\-]{40,80}"##).unwrap(), 0), // NVIDIA
            (KeyKind::HuggingFace, Regex::new(r##"hf_[A-Za-z0-9]{34,}"##).unwrap(), 0), // HUGGINGFACE
            (KeyKind::Xai, Regex::new(r##"xai-[A-Za-z0-9_]{40,100}"##).unwrap(), 0), // GROK
            (KeyKind::Generic, Regex::new(r##"\bmsh_[A-Za-z0-9]{30,40}\b"##).unwrap(), 0), // MESHY
            (KeyKind::Generic, Regex::new(r##"\bluma-[a-z0-9]{8}-[a-z0-9]{8}-[a-z0-9]{8}\b"##).unwrap(), 0), // LUMA
            (KeyKind::Generic, Regex::new(r##"(?:mistral|MISTRAL)[_a-zA-Z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{32})"##).unwrap(), 1), // MISTRAL
            (KeyKind::Generic, Regex::new(r##"tgp_[A-Za-z0-9\-]{40,60}"##).unwrap(), 0), // TOGETHER
            (KeyKind::Generic, Regex::new(r##"r8_[A-Za-z0-9]{37}"##).unwrap(), 0), // REPLICATE
            (KeyKind::Generic, Regex::new(r##"csk-[a-z0-9]{60}"##).unwrap(), 0), // CEREBRAS
            (KeyKind::Generic, Regex::new(r##"\bfea_[A-Za-z0-9]{30,}\b"##).unwrap(), 0), // FEATHERLESS
            (KeyKind::Generic, Regex::new(r##"\bbbs_[A-Za-z0-9]{30,}\b"##).unwrap(), 0), // BROWSERBASE
            (KeyKind::Generic, Regex::new(r##"\bAk-[A-Za-z0-9]{40}\b"##).unwrap(), 0), // MODAL_TOKEN
            (KeyKind::Generic, Regex::new(r##"\bico-[a-zA-Z0-9]{32}\b"##).unwrap(), 0), // INFRACOST
            (KeyKind::HuggingFace, Regex::new(r##"\bapi_org_[A-Za-z0-9]{34}\b"##).unwrap(), 0), // HF_ORG
            (KeyKind::Generic, Regex::new(r##"\bglrt-[A-Za-z0-9_\-]{20,}\b"##).unwrap(), 0), // GITLAB_ROUTABLE
            (KeyKind::Generic, Regex::new(r##"(?:2captcha|rucaptcha|twocaptcha|two_captcha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{32})"##).unwrap(), 1), // TWOCAPTCHA
            (KeyKind::Generic, Regex::new(r##"(?:capsolver|cap_solver)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(CAP-[A-Za-z0-9_-]{20,45})"##).unwrap(), 1), // CAPSOLVER
            (KeyKind::Generic, Regex::new(r##"(?:anticaptcha|anti_captcha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})"##).unwrap(), 1), // ANTICAPTCHA
            (KeyKind::Generic, Regex::new(r##"(?:capmonster|cap_monster)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})"##).unwrap(), 1), // CAPMONSTER
            (KeyKind::Generic, Regex::new(r##"(?:ezsolver|ez_solver)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{32})"##).unwrap(), 1), // EZSOLVER
            (KeyKind::Generic, Regex::new(r##"(?:nopecha|nope_cha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,64})"##).unwrap(), 1), // NOPECHA
            (KeyKind::Generic, Regex::new(r##"(?:azcaptcha|az_captcha)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{32})"##).unwrap(), 1), // AZCAPTCHA
            (KeyKind::Generic, Regex::new(r##"(?:yessolver|yes_solver)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9]{32,64})"##).unwrap(), 1), // YESSOLVER
            (KeyKind::Generic, Regex::new(r##"2captcha\.com/in\.\w+\?key=([a-f0-9]{32})"##).unwrap(), 1), // TWOCAPTCHA_URL
            (KeyKind::Generic, Regex::new(r##"(?:soax|SOAX)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,50})"##).unwrap(), 1), // SOAX
            (KeyKind::Generic, Regex::new(r##"socks5://(?:[^:@]+:[^@]+@)?[^\s"\'<>]+:\d{2,5}"##).unwrap(), 0), // PROXY_SOCKS5
            (KeyKind::Generic, Regex::new(r##"https?://(?:[^:@]+:[^@]+@)?[^\s"\'<>]+:\d{2,5}"##).unwrap(), 0), // PROXY_HTTP
            (KeyKind::Generic, Regex::new(r##"dtn_[a-f0-9]{64}"##).unwrap(), 0), // DAYTONA
            (KeyKind::Generic, Regex::new(r##"(?:webshare)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"##).unwrap(), 1), // WEBSHARE
            (KeyKind::Generic, Regex::new(r##"(?:iproyal|ip_royal)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-zA-Z0-9_-]{20,50})"##).unwrap(), 1), // IPROYAL
            (KeyKind::Generic, Regex::new(r##"(?:brightdata|luminati|brd)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})"##).unwrap(), 1), // BRIGHTDATA
            (KeyKind::Generic, Regex::new(r##"\b\d{8,10}:AA[A-Za-z0-9_\-]{33}\b"##).unwrap(), 0), // TELEGRAM
            (KeyKind::Generic, Regex::new(r##"\b1[A-Z][A-Za-z0-9_\-]{340,380}\b"##).unwrap(), 0), // TELEGRAM_SESSION
            (KeyKind::Generic, Regex::new(r##"\bBQ[A-Za-z0-9_\-]{340,}\b"##).unwrap(), 0), // TELEGRAM_PYROGRAM
            (KeyKind::Generic, Regex::new(r##"mfa\.[A-Za-z0-9_\-]{24,120}"##).unwrap(), 0), // DISCORD
            (KeyKind::Generic, Regex::new(r##"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}"##).unwrap(), 0), // DISCORD
            (KeyKind::OpenAi, Regex::new(r##"sk-proj-[A-Za-z0-9_-]{60,200}|sk-svcacct-[A-Za-z0-9_-]{60,200}|sk-None-[A-Za-z0-9_-]{20,200}|"sk-[A-Za-z0-9]{20}iv|"sk-[A-Za-z0-9]{20}proj"##).unwrap(), 0), // OPENAI
            (KeyKind::Anthropic, Regex::new(r##"sk-ant-api03-[A-Za-z0-9_-]{20,120}"##).unwrap(), 0), // ANTHROPIC
            (KeyKind::Anthropic, Regex::new(r##"sk-ant-oat01-[A-Za-z0-9_-]{40,120}"##).unwrap(), 0), // ANTHROPIC_OAT
            (KeyKind::Google, Regex::new(r##"(?:GOOGLE|google|GCP|gcp)[_ ]?(?:API|APPLICATION_CREDENTIALS|AI)[_ ]?(?:KEY|TOKEN|CREDENTIALS|FILE)?[\'"]?\s*[=:]\s*[\'"]?(AIza[A-Za-z0-9_-]{35})"##).unwrap(), 1), // GOOGLE
            (KeyKind::Google, Regex::new(r##"AIza[A-Za-z0-9_-]{35}"##).unwrap(), 0), // GOOGLE
            (KeyKind::Generic, Regex::new(r##"LTAI[A-Za-z0-9]{12,20}"##).unwrap(), 0), // ALIYUN
            (KeyKind::Generic, Regex::new(r##"AKIA[A-Z0-9]{16}"##).unwrap(), 0), // AWS
            (KeyKind::Generic, Regex::new(r##"(?:cf_|CF_)[A-Za-z0-9_-]{40,50}"##).unwrap(), 0), // CLOUDFLARE
            (KeyKind::Generic, Regex::new(r##"sk_live_[A-Za-z0-9]{24,}"##).unwrap(), 0), // STRIPE
            (KeyKind::GithubPat, Regex::new(r##"ghp_[A-Za-z0-9]{36,}"##).unwrap(), 0), // GITHUB_PAT
            (KeyKind::GithubPat, Regex::new(r##"gho_[A-Za-z0-9]{36}"##).unwrap(), 0), // GITHUB_OAUTH
            (KeyKind::GithubPat, Regex::new(r##"ghu_[A-Za-z0-9]{36,45}"##).unwrap(), 0), // GITHUB_USER
            (KeyKind::GithubPat, Regex::new(r##"ghs_[A-Za-z0-9]{36,45}"##).unwrap(), 0), // GITHUB_SERVER
            (KeyKind::GithubPat, Regex::new(r##"ghr_[A-Za-z0-9]{76,90}"##).unwrap(), 0), // GITHUB_REFRESH
            (KeyKind::GithubPat, Regex::new(r##"github_pat_[A-Za-z0-9_]{82}"##).unwrap(), 0), // GITHUB_FINE
            (KeyKind::Generic, Regex::new(r##"xoxb-[0-9]{8,12}-[0-9]{8,12}-[A-Za-z0-9]{20,24}"##).unwrap(), 0), // SLACK_BOT
            (KeyKind::Generic, Regex::new(r##"xoxp-[0-9]{8,12}-[0-9]{8,12}-[0-9]{8,12}-[A-Za-z0-9]{20,30}"##).unwrap(), 0), // SLACK_USER
            (KeyKind::Generic, Regex::new(r##"xapp-[0-9]-[A-Za-z0-9-]{20,}"##).unwrap(), 0), // SLACK_APP
            (KeyKind::Generic, Regex::new(r##"lin_api_[A-Za-z0-9]{40}"##).unwrap(), 0), // LINEAR
            (KeyKind::Generic, Regex::new(r##"sntrys_[A-Za-z0-9_\-]{60,}"##).unwrap(), 0), // SENTRY
            (KeyKind::Generic, Regex::new(r##"figd_[A-Za-z0-9]{40}"##).unwrap(), 0), // FIGMA
            (KeyKind::Generic, Regex::new(r##"PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{43}"##).unwrap(), 0), // POSTMAN
            (KeyKind::Generic, Regex::new(r##"secret_[A-Za-z0-9]{43}"##).unwrap(), 0), // NOTION_BARE
            (KeyKind::Generic, Regex::new(r##"upstash_[A-Za-z0-9]{30,40}"##).unwrap(), 0), // UPSTASH
            (KeyKind::Generic, Regex::new(r##"npm_[A-Za-z0-9]{36}"##).unwrap(), 0), // NPM
            (KeyKind::Generic, Regex::new(r##"pypi-[A-Za-z0-9_-]{50,}"##).unwrap(), 0), // PYPI
            (KeyKind::Generic, Regex::new(r##"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"##).unwrap(), 0), // SENDGRID
            (KeyKind::Generic, Regex::new(r##"(?:twilio|TWILIO)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32})"##).unwrap(), 1), // TWILIO
            (KeyKind::Generic, Regex::new(r##"(?:notion|NOTION)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(secret_[A-Za-z0-9]{43})"##).unwrap(), 1), // NOTION
            (KeyKind::Generic, Regex::new(r##"(?:pinecone|PINECONE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"##).unwrap(), 1), // PINECONE
            (KeyKind::Generic, Regex::new(r##"(?:wandb|WANDB)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{40})"##).unwrap(), 1), // WANDB
            (KeyKind::Generic, Regex::new(r##"(?:runpod|RUNPOD)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,50})"##).unwrap(), 1), // RUNPOD
            (KeyKind::Generic, Regex::new(r##"SK[0-9a-f]{32}"##).unwrap(), 0), // TWILIO_SK
            (KeyKind::Generic, Regex::new(r##"glpat-[0-9a-zA-Z_-]{20,}"##).unwrap(), 0), // GITLAB_PAT
            (KeyKind::Generic, Regex::new(r##"postgres(?:ql)?://[^\s\"'<>]{1,64}:[^\s\"'@<>]{4,}@[^\s\"'<>]+"##).unwrap(), 0), // PG_URI
            (KeyKind::Generic, Regex::new(r##"mysql://[^\s\"'<>]{1,64}:[^\s\"'@<>]{4,}@[^\s\"'<>]+"##).unwrap(), 0), // MYSQL_URI
            (KeyKind::Generic, Regex::new(r##"mongodb(?:\+srv)?://[^\s\"'<>]{1,64}:[^\s\"'@<>]{4,}@[^\s\"'<>]+"##).unwrap(), 0), // MONGO_URI
            (KeyKind::Generic, Regex::new(r##"rediss?://:[^\s\"'@<>]{4,}@[^\s\"'<>]+"##).unwrap(), 0), // REDIS_URI
            (KeyKind::Generic, Regex::new(r##"https://[^\s\"'/:@<>]{1,64}:[^\s\"'@/<>]{4,}@[^\s\"'<>]+"##).unwrap(), 0), // HTTPS_AUTH
            (KeyKind::Generic, Regex::new(r##"DefaultEndpointsProtocol=https;AccountName=[a-z0-9][a-z0-9-]{1,22}[a-z0-9];AccountKey=[A-Za-z0-9+/]{86}=="##).unwrap(), 0), // AZURE_STORAGE
            (KeyKind::Generic, Regex::new(r##"napi_[A-Za-z0-9]{30,60}"##).unwrap(), 0), // NEON
            (KeyKind::Generic, Regex::new(r##"sl\.[A-Za-z0-9_-]{100,150}"##).unwrap(), 0), // DROPBOX
            (KeyKind::Generic, Regex::new(r##"AAAAAAAAA[A-Za-z0-9%]{50,90}"##).unwrap(), 0), // TWITTER
            (KeyKind::Generic, Regex::new(r##"xkeysib-[A-Za-z0-9]{16,64}-[A-Za-z0-9]{16,64}"##).unwrap(), 0), // BREVO
            (KeyKind::Generic, Regex::new(r##"re_[A-Za-z0-9]{28,50}"##).unwrap(), 0), // RESEND
            (KeyKind::Generic, Regex::new(r##"\bkey-[a-f0-9]{32}\b"##).unwrap(), 0), // MAILGUN
            (KeyKind::Generic, Regex::new(r##"shp(?:at|ca|ss|pa|ua)_[a-fA-F0-9]{32}"##).unwrap(), 0), // SHOPIFY
            (KeyKind::Generic, Regex::new(r##"sq0atp-[A-Za-z0-9_-]{22,60}"##).unwrap(), 0), // SQUARE
            (KeyKind::Generic, Regex::new(r##"sq0csp-[A-Za-z0-9_-]{40,60}"##).unwrap(), 0), // SQUARE_SECRET
            (KeyKind::Generic, Regex::new(r##"whsec_[A-Za-z0-9]{32,64}"##).unwrap(), 0), // STRIPE_WEBHOOK
            (KeyKind::Generic, Regex::new(r##"rk_live_[A-Za-z0-9]{24,99}"##).unwrap(), 0), // STRIPE_RESTRICTED
            (KeyKind::Generic, Regex::new(r##"do[po]_v1_[a-f0-9]{64}"##).unwrap(), 0), // DIGITALOCEAN
            (KeyKind::Generic, Regex::new(r##"dckr_pat_[A-Za-z0-9_-]{30,}"##).unwrap(), 0), // DOCKER
            (KeyKind::Generic, Regex::new(r##"KakaoAK [0-9a-f]{32}"##).unwrap(), 0), // KAKAO
            (KeyKind::Generic, Regex::new(r##"rubygems_[A-Za-z0-9]{30,}"##).unwrap(), 0), // RUBYGEMS_PAT
            (KeyKind::Generic, Regex::new(r##"squ_[A-Za-z0-9]{40,}"##).unwrap(), 0), // SONARQUBE
            (KeyKind::Generic, Regex::new(r##"glc_[A-Za-z0-9_-]{40,}"##).unwrap(), 0), // GRAFANA
            (KeyKind::Generic, Regex::new(r##"lsv2_(?:pt|sk)_[A-Za-z0-9]{40,}"##).unwrap(), 0), // LANGSMITH
            (KeyKind::Generic, Regex::new(r##"tvly-[A-Za-z0-9]{26,48}"##).unwrap(), 0), // TAVILY
            (KeyKind::Generic, Regex::new(r##"fc-[a-f0-9]{32}"##).unwrap(), 0), // FIRECRAWL
            (KeyKind::Generic, Regex::new(r##"nfp_[A-Za-z0-9]{40,46}"##).unwrap(), 0), // NETLIFY
            (KeyKind::Generic, Regex::new(r##"rnd_[A-Za-z0-9]{32,}"##).unwrap(), 0), // RENDER
            (KeyKind::Generic, Regex::new(r##"sk\.eyJ[A-Za-z0-9_\-]{50,}"##).unwrap(), 0), // MAPBOX_SECRET
            (KeyKind::Generic, Regex::new(r##"pat-(?:na|eu)\d-[A-Za-z0-9]{30,}"##).unwrap(), 0), // HUBSPOT
            (KeyKind::Generic, Regex::new(r##"pat[A-Za-z0-9]{8,20}\.[A-Za-z0-9]{40,}"##).unwrap(), 0), // AIRTABLE
            (KeyKind::Generic, Regex::new(r##"https://[a-f0-9]{32}@[a-z0-9.-]*sentry\.io/\d+"##).unwrap(), 0), // SENTRY_DSN
            (KeyKind::Generic, Regex::new(r##"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,6000}?-----END [A-Z ]*PRIVATE KEY-----"##).unwrap(), 0), // PRIVATE_KEY
            (KeyKind::Generic, Regex::new(r##"\b[a-f0-9]{32}-us\d{1,2}\b"##).unwrap(), 0), // MAILCHIMP
            (KeyKind::Generic, Regex::new(r##"access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}"##).unwrap(), 0), // ACCTOKEN
            (KeyKind::Generic, Regex::new(r##"jina_[A-Fa-f0-9]{20,50}"##).unwrap(), 0), // JINA
            (KeyKind::Generic, Regex::new(r##"pa-[A-Za-z0-9_-]{20,60}"##).unwrap(), 0), // VOYAGE
            (KeyKind::Generic, Regex::new(r##"BSA[A-Za-z0-9_-]{20,80}"##).unwrap(), 0), // BRAVE_SEARCH
            (KeyKind::Generic, Regex::new(r##"bfl_[A-Za-z0-9_-]{20,60}"##).unwrap(), 0), // BFL
            (KeyKind::Generic, Regex::new(r##"di_[A-Za-z0-9]{30,80}"##).unwrap(), 0), // DEEPINFRA
            (KeyKind::Generic, Regex::new(r##"(?:pk-lf-|sk-lf-)[A-Za-z0-9_-]{20,80}"##).unwrap(), 0), // LANGFUSE
            (KeyKind::Generic, Regex::new(r##"pcsk_[A-Za-z0-9_-]{30,80}"##).unwrap(), 0), // PINECONE_V2
            (KeyKind::Generic, Regex::new(r##"(?:BASETEN|baseten)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // BASETEN
            (KeyKind::Generic, Regex::new(r##"(?:SERPER|serper)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(sp_[A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // SERPER
            (KeyKind::Generic, Regex::new(r##"(?:SERPAPI|serpapi)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9]{30,80})"##).unwrap(), 1), // SERPAPI
            (KeyKind::Generic, Regex::new(r##"(?:EXA|exa)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // EXA
            (KeyKind::Generic, Regex::new(r##"(?:RUNWAY|runway|RUNWAYML)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // RUNWAY
            (KeyKind::Generic, Regex::new(r##"(?:PIKA|pika)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // PIKA
            (KeyKind::Generic, Regex::new(r##"(?:SUNO|suno)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(sk-[A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // SUNO
            (KeyKind::Generic, Regex::new(r##"(?:FLY|fly)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,80})"##).unwrap(), 1), // FLYIO
            (KeyKind::Generic, Regex::new(r##"(?:TENCENT|tencent|HUNYUAN|hunyuan)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // TENCENT
            (KeyKind::Generic, Regex::new(r##"(?:SAMBANOVA|sambanova)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // SAMBANOVA
            (KeyKind::Generic, Regex::new(r##"(?:UPSTAGE|upstage)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // UPSTAGE
            (KeyKind::Generic, Regex::new(r##"(?:LEPTON|lepton)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // LEPTON
            (KeyKind::Generic, Regex::new(r##"(?:NEARAI|nearai|NEAR_AI)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // NEARAI
            (KeyKind::Generic, Regex::new(r##"(?:ALEPH_ALPHA|aleph_alpha|ALEPHALPHA)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // ALEPH_ALPHA
            (KeyKind::Generic, Regex::new(r##"(?:AI21|ai21)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // AI21
            (KeyKind::Generic, Regex::new(r##"\bglsa_[A-Za-z0-9_\-]{20,}\b"##).unwrap(), 0), // GRAFANA_SA
            (KeyKind::Generic, Regex::new(r##"\bNRAK-[A-Za-z0-9]{27}\b"##).unwrap(), 0), // NEWRELIC
            (KeyKind::Generic, Regex::new(r##"\bpul-[a-f0-9]{40}\b"##).unwrap(), 0), // PULUMI
            (KeyKind::Google, Regex::new(r##"\bya29\.[0-9A-Za-z\-_]{50,}\b"##).unwrap(), 0), // GOOGLE_CLOUD_OAUTH
            (KeyKind::Generic, Regex::new(r##"\bAAAA[A-Za-z0-9\-_]{40,}:[A-Za-z0-9\-_]{40,}\b"##).unwrap(), 0), // FIREBASE_SERVER
            (KeyKind::Generic, Regex::new(r##"\bAccessToken\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b"##).unwrap(), 0), // PAYPAL
            (KeyKind::Generic, Regex::new(r##"\bAC[0-9a-f]{32}\b"##).unwrap(), 0), // TWILIO_AC
            (KeyKind::Generic, Regex::new(r##"\bcb-[A-Za-z0-9_\-]{20,}\b"##).unwrap(), 0), // COINBASE
            (KeyKind::Generic, Regex::new(r##"\bhttps://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+\b"##).unwrap(), 0), // DISCORD_WEBHOOK
            (KeyKind::Generic, Regex::new(r##"\bhttps://hooks\.slack\.com/services/[A-Z0-9]{9}/[A-Z0-9]{9}/[A-Za-z0-9]{24}\b"##).unwrap(), 0), // SLACK_WEBHOOK
            (KeyKind::Generic, Regex::new(r##"\b00D[A-Za-z0-9]{12,}![A-Za-z0-9_\-]{20,}\b"##).unwrap(), 0), // SALESFORCE
            (KeyKind::Generic, Regex::new(r##"_auth\s*=\s*[A-Za-z0-9+/=]{20,}"##).unwrap(), 0), // NPM_RC_AUTH
            (KeyKind::Generic, Regex::new(r##"\bFwoGZXIvYXdzE[A-Za-z0-9+/=]{100,}"##).unwrap(), 0), // AWS_STS
            (KeyKind::Generic, Regex::new(r##"\boy2[a-zA-Z0-9]{43}\b"##).unwrap(), 0), // NUGET
            (KeyKind::Generic, Regex::new(r##"\bpscale_[A-Za-z0-9_\-]{20,}\b"##).unwrap(), 0), // PLANETSCALE
            (KeyKind::Generic, Regex::new(r##"(?:\?|&)sv=\d{4}-\d{2}-\d{2}[^\s"\'<>]*sig=[^\s"\'<>]+"##).unwrap(), 0), // AZURE_SAS
            (KeyKind::Generic, Regex::new(r##"\bGR1348941[A-Za-z0-9_\-]{20,}\b"##).unwrap(), 0), // GITLAB_RUNNER
            (KeyKind::Generic, Regex::new(r##"\bsgp_[a-f0-9]{40}\b"##).unwrap(), 0), // SOURCEGRAPH
            (KeyKind::Generic, Regex::new(r##"\bapify_api_[A-Za-z0-9]{36}\b"##).unwrap(), 0), // APIFY
            (KeyKind::Generic, Regex::new(r##"(?:ONE_API|NEW_API|one-api|new-api|ONEAPI|NEWAPI)[_\s]*(?:URL|HOST|BASE|ENDPOINT)\s*[=:]\s*["\']?(https?://[^\s"\']{10,200})|(?:DIFY|dify)[_\s]*(?:URL|HOST|BASE|ENDPOINT|API)[_\s]*[=:]\s*["\']?(https?://[^\s"\']{10,200})|(?:FASTGPT|fastgpt)[_\s]*(?:URL|HOST|BASE)[_\s]*[=:]\s*["\']?(https?://[^\s"\']{10,200})|(?:LOBECHAT|lobechat)[_\s]*(?:URL|HOST|BASE|PROXY)[_\s]*[=:]\s*["\']?(https?://[^\s"\']{10,200})|(?:OPENWEBUI|openwebui)[_\s]*(?:URL|HOST|BASE)[_\s]*[=:]\s*["\']?(https?://[^\s"\']{10,200})|(?:OLLAMA|ollama)[_\s]*(?:HOST|URL|BASE)[_\s]*[=:]\s*["\']?(https?://[^\s"\']{10,200})"##).unwrap(), 1), // ENDPOINT_CN
            (KeyKind::Anthropic, Regex::new(r##"sk-ant-api\d{2}-[A-Za-z0-9_-]{90,110}"##).unwrap(), 0), // ANTHROPIC
            (KeyKind::Generic, Regex::new(r##"tvly-[A-Za-z0-9_-]{20,50}"##).unwrap(), 0), // TAVILY
            (KeyKind::Generic, Regex::new(r##"BSA-[A-Za-z0-9]{20,50}"##).unwrap(), 0), // BRAVE_SEARCH
            (KeyKind::Generic, Regex::new(r##"(?:deepinfra|DEEPINFRA)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // DEEPINFRA
            (KeyKind::Generic, Regex::new(r##"(?:hyperbolic|HYPERBOLIC)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,80})"##).unwrap(), 1), // HYPERBOLIC
            (KeyKind::Generic, Regex::new(r##"(?:writer|WRITER)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // WRITER
            (KeyKind::Generic, Regex::new(r##"(?:qroq|QROQ)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // QROQ
            (KeyKind::Generic, Regex::new(r##"(?:openpipe|OPENPIPE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(opk-[A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // OPENPIPE
            (KeyKind::Generic, Regex::new(r##"(?:octoai|OCTOAI|octoml)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // OCTOAI
            (KeyKind::Generic, Regex::new(r##"(?:predibase|PREDIBASE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // PREDIBASE
            (KeyKind::Generic, Regex::new(r##"(?:vllm|VLLM)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // VLLM
            (KeyKind::Generic, Regex::new(r##"(?:abacus|ABACUS)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // ABACUS
            (KeyKind::Generic, Regex::new(r##"(?:lambdalabs|lambda_labs|LAMBDA)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // LAMBDA
            (KeyKind::Generic, Regex::new(r##"(?:anyscale|ANYSCALE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(ese-[A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // ANYSCALE
            (KeyKind::Generic, Regex::new(r##"(?:stepfun|STEPFUN)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // STEPFUN
            (KeyKind::Generic, Regex::new(r##"(?:lingyi|LINGYI|lingyiwanwu|01ai|01\.ai|01_ai|yi_api|YI_API)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // LINGYI
            (KeyKind::Generic, Regex::new(r##"(?:baichuan|BAICHUAN|百川)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // BAICHUAN
            (KeyKind::Generic, Regex::new(r##"(?:iflytek|IFLYTEK|spark|SPARK|讯飞)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // IFLYTEK
            (KeyKind::Generic, Regex::new(r##"(?:vanchin|VANCHIN)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // VANCHIN
            (KeyKind::Generic, Regex::new(r##"(?:baidu_bce|BAIDU_BCE|bce-v[0-9])[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // BAIDU_BCE
            (KeyKind::Generic, Regex::new(r##"(?:huawei|HUAWEI|huaweicloud|HW_CLOUD)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // HUAWEI_CLOUD
            (KeyKind::Generic, Regex::new(r##"(?:bytedance|BYTEDANCE|volcengine|VOLCENGINE|volces|VOLCES)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // BYTEDANCE_VOLCE
            (KeyKind::Generic, Regex::new(r##"(?:tencentcloud|TENCENTCLOUD|tencent_cloud)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,60})"##).unwrap(), 1), // TENCENT_CLOUD
            (KeyKind::Generic, Regex::new(r##"(?:deepkey|DEEPKEY)[_\s]*(?:API)?[_a-z]{0,10}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // DEEPKEY
            (KeyKind::Generic, Regex::new(r##"(?:teamorouter|TEAMOROUTER|teamo_router)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // TEAMOROUTER
            (KeyKind::Generic, Regex::new(r##"(?:yunwu|YUNWU|云雾)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // YUNWU
            (KeyKind::Generic, Regex::new(r##"(?:claudmax|CLAUDMAX)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // CLAUDMAX
            (KeyKind::Generic, Regex::new(r##"(?:omniroute|OMNIROUTE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // OMNIROUTE
            (KeyKind::Generic, Regex::new(r##"(?:kissapi|KISSAPI|kiss_api)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // KISSAPI
            (KeyKind::Generic, Regex::new(r##"(?:allrouter|ALLROUTER)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // ALLROUTER
            (KeyKind::Generic, Regex::new(r##"(?:unorouter|UNOROUTER)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // UNOROUTER
            (KeyKind::Generic, Regex::new(r##"(?:quicksilver|QUICKSILVER)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // QUICKSILVER
            (KeyKind::Generic, Regex::new(r##"(?:tokens.forge|tokens_forge|TOKENSFORGE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // TOKENSFORGE
            (KeyKind::Generic, Regex::new(r##"(?:freeai|FREEAI|free_ai)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // FREEAI
            (KeyKind::Generic, Regex::new(r##"(?:aiapi.pro|aiapi_pro|AIAPI_PRO)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // AIAPI_PRO
            (KeyKind::Generic, Regex::new(r##"(?:atlascloud|ATLASCLOUD)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // ATLASCLOUD
            (KeyKind::Generic, Regex::new(r##"(?:coderplan|coder_plan|CODERPLAN|CPLAN)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})"##).unwrap(), 1), // CPLAN_AI
            (KeyKind::Generic, Regex::new(r##"(?:stripe|STRIPE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(sk_live_[A-Za-z0-9]{20,})"##).unwrap(), 1), // STRIPE
            (KeyKind::Generic, Regex::new(r##"(?:stripe|STRIPE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(sk_test_[A-Za-z0-9]{20,})"##).unwrap(), 1), // STRIPE_TEST
            (KeyKind::Generic, Regex::new(r##"(?:notion|NOTION)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(ntn_[A-Za-z0-9]{30,}|secret_[A-Za-z0-9]{40,})"##).unwrap(), 1), // NOTION
            (KeyKind::Generic, Regex::new(r##"(?:sentry|SENTRY)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{64})"##).unwrap(), 1), // SENTRY
            (KeyKind::Generic, Regex::new(r##"https://[a-f0-9]{32}@sentry\.io/\d+"##).unwrap(), 0), // SENTRY_DSN
            (KeyKind::GithubPat, Regex::new(r##"ghp_[A-Za-z0-9]{36,40}|github_pat_[A-Za-z0-9_]{40,60}"##).unwrap(), 0), // GITHUB_PAT
            (KeyKind::GithubPat, Regex::new(r##"gho_[A-Za-z0-9]{36,40}"##).unwrap(), 0), // GITHUB_FG
            (KeyKind::Generic, Regex::new(r##"glpat-[A-Za-z0-9_\-]{20,}"##).unwrap(), 0), // GITLAB_PAT
            (KeyKind::Generic, Regex::new(r##"(?:cloudflare|CLOUDFLARE|CF)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // CLOUDFLARE
            (KeyKind::Generic, Regex::new(r##"(?:cf_token|CF_TOKEN|cloudflare_token)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // CLOUDFLARE_TOKEN
            (KeyKind::Generic, Regex::new(r##"(?:confluent|CONFLUENT)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // CONFLUENT
            (KeyKind::Generic, Regex::new(r##"(?:mongodb.atlas|mongodb_atlas|MONGODB_ATLAS|MONGODB)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // MONGODB_ATLAS
            (KeyKind::Generic, Regex::new(r##"(?:elastic.cloud|elastic_cloud|ELASTIC_CLOUD|elasticsearch)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // ELASTIC_CLOUD
            (KeyKind::Generic, Regex::new(r##"(?:upstash|UPSTASH)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // UPSTASH
            (KeyKind::Generic, Regex::new(r##"(?:neon|NEON)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // NEON
            (KeyKind::Generic, Regex::new(r##"(?:planetscale|PLANETSCALE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // PLANETSCALE_DB
            (KeyKind::Generic, Regex::new(r##"(?:supabase_service|SUPABASE_SERVICE|supabase_key)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // SUPABASE_SERVICE
            (KeyKind::Generic, Regex::new(r##"(?:deepgram|DEEPGRAM)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // DEEPGRAM
            (KeyKind::Generic, Regex::new(r##"(?:assemblyai|ASSEMBLYAI)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // ASSEMBLYAI
            (KeyKind::Generic, Regex::new(r##"(?:gladia|GLADIA)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // GLADIA
            (KeyKind::Generic, Regex::new(r##"(?:leonardo|LEONARDO)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // LEONARDO
            (KeyKind::Generic, Regex::new(r##"(?:synthesia|SYNTHESIA)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // SYNTHESIA
            (KeyKind::Generic, Regex::new(r##"(?:clipdrop|CLIPDROP)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // CLIPDROP
            (KeyKind::Generic, Regex::new(r##"(?:rev.ai|rev_ai|REV)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // REV_AI
            (KeyKind::Generic, Regex::new(r##"(?:speechmatics|SPEECHMATICS)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // SPEECHMATICS
            (KeyKind::Generic, Regex::new(r##"(?:scrapingbee|SCRAPINGBEE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // SCRAPINGBEE
            (KeyKind::Generic, Regex::new(r##"(?:zenrows|ZENROWS)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // ZENROWS
            (KeyKind::Generic, Regex::new(r##"(?:brightdata|BRIGHTDATA|bright_data)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // BRIGHTDATA
            (KeyKind::Generic, Regex::new(r##"(?:oxylabs|OXYLABS|oxy_labs)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // OXYLABS
            (KeyKind::Generic, Regex::new(r##"(?:crewai|CREWAI)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // CREWAI
            (KeyKind::Generic, Regex::new(r##"(?:composio|COMPOSIO)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // COMPOSIO
            (KeyKind::Generic, Regex::new(r##"(?:n8n|N8N)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // N8N
            (KeyKind::Generic, Regex::new(r##"(?:flowise|FLOWISE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // FLOWISE
            (KeyKind::Generic, Regex::new(r##"(?:langflow|LANGFLOW)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // LANGFLOW
            (KeyKind::Generic, Regex::new(r##"(?:helicone|HELICONE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // HELICONE
            (KeyKind::Generic, Regex::new(r##"(?:braintrust|BRAINTRUST)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // BRAINTRUST
            (KeyKind::Generic, Regex::new(r##"(?:datadog|DATADOG|DD)[_a-zA-Z]{0,15}["\']?\s*[=:]\s*["\']?([a-f0-9]{32,40})"##).unwrap(), 1), // DATADOG
            (KeyKind::Generic, Regex::new(r##"(?:hubspot|HUBSPOT)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // HUBSPOT
            (KeyKind::Generic, Regex::new(r##"(?:intercom|INTERCOM)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // INTERCOM
            (KeyKind::Generic, Regex::new(r##"(?:bitbucket|BITBUCKET|BB)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,60})"##).unwrap(), 1), // BITBUCKET_APP
            (KeyKind::Generic, Regex::new(r##"(?:azure_devops|AZURE_DEVOPS|ado_)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?([A-Za-z0-9_-]{30,80})"##).unwrap(), 1), // AZURE_DEVOPS
            (KeyKind::Generic, Regex::new(r##"(?:api.key|API.KEY|api_key|API_KEY|apikey|APIKEY|密钥|秘钥|key)\s*[:=：]\s*["\']?(sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // API_KEY_ZH
            (KeyKind::DashScope, Regex::new(r##"(?:DashScope|dashscope|阿里云|百炼|灵积|通义|千问|qwen|tongyi|bailian)[^=]{0,80}["\']?(sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // DASHSCOPE_ZH
            (KeyKind::Generic, Regex::new(r##"(?:中转|代理|接口|gateway|proxy|relay|router)[^=]{0,80}["\']?(sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // GATEWAY_ZH
            (KeyKind::OpenAi, Regex::new(r##"(?:OPENAI_BASE_URL|OPENAI_API_BASE|api_base|base_url|API_BASE)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(https?://[^\s"\']{10,200})["\']?\s*(?:.*?["\']?(sk-[A-Za-z0-9_-]{20,200}))?"##).unwrap(), 1), // OPENAI_COMPAT
            (KeyKind::Anthropic, Regex::new(r##"(?:ANTHROPIC_BASE_URL|ANTHROPIC_API_BASE|claude_base)[_a-z]{0,15}["\']?\s*[=:]\s*["\']?(https?://[^\s"\']{10,200})"##).unwrap(), 1), // ANTHROPIC_COMPAT
            (KeyKind::Generic, Regex::new(r##"(?:base_url|api_base|host|endpoint|api_url|BASE_URL|API_BASE|HOST|ENDPOINT|API_URL)\s*[=:]\s*["\']?(?:https?://[^\s"\'\,"\n]{8,150})["\']?[\s\S]{0,200}?(?:api_key|key|token|api|API_KEY|KEY|TOKEN)\s*[=:]\s*["\']?(sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // GATEWAY_PAIR
            (KeyKind::Generic, Regex::new(r##"(?:url|base_url|host|endpoint)\s*:\s*["\']?(?:https?://[^\s"\'\,"\n]{8,150})["\']?[\s\S]{0,200}?(?:key|api_key|token)\s*:\s*["\']?(sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // GATEWAY_YAML
            (KeyKind::Generic, Regex::new(r##"(?:https?://[^\s"\']{8,150}/v1(?:/chat(?:/completions)?)?)[\s\S]{0,150}?(sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // GATEWAY_INLINE
            (KeyKind::Generic, Regex::new(r##"(?:\u4e2d\u8f6c|\u4ee3\u7406|\u63a5\u53e3|relay|proxy|gateway|api)[^\n]{0,100}?(?:https?://[^\s"\'\,"\n]{8,150})[\s\S]{0,200}?(sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // RELAY_CN
            (KeyKind::Generic, Regex::new(r##"(?:https?://[^\s"\']{0,60}?(?:deepkey|yunwu|teamorouter|allrouter|unorouter|quicksilver|aiapi-pro|atlascloud|tokensforge|freeai|aimlapi|relaydance|sandbase|routescope|aiapk|bltcy|uiuiapi|dmxapi|mkeai|gptgod|closeai|xuanshu|wawazz|tokendos|dshapi|coderplan)[^\s"\']{0,80})[\s\S]{0,200}?(sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // GATEWAY_SPECIFIC
            (KeyKind::Generic, Regex::new(r##"(?:LITELLM_MASTER_KEY|litellm_master_key|master_key)\s*[=:]\s*["\']?(sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // LITELLM_MASTER
            (KeyKind::Generic, Regex::new(r##"(?:new.api|one.api|newapi|oneapi)[^\n]{0,60}?["\']?\s*[=:]\s*["\'](sk-[A-Za-z0-9_-]{20,200})"##).unwrap(), 1), // NEWAPI_KEY
(KeyKind::Generic, Regex::new(r#"(?i)\b(?:DASHSCOPE_TOKEN|DASHSCOPE_KEY|DASHSCOPE_LLM_API_KEY|DASH_SCOPE_API_KEY|ALIYUN_DASHSCOPE_API_KEY|BAILIAN_TOKEN|BAILIAN_KEY|QWEN_TOKEN|QWEN_KEY|QWEN_LLM_API_KEY|QWEN_DASHSCOPE_API_KEY|TONGYI_API_KEY|TONGYI_TOKEN|TONGYI_QIANWEN_API_KEY|TONGYI_QIANWEN_TOKEN|EXA_API_KEY|FIRECRAWL_API_KEY|TAVILY_API_KEY|SERPER_API_KEY|SERPAPI_API_KEY|APIFY_API_TOKEN|HUNTER_API_KEY|HUNTERIO_API_KEY|BRAVE_SEARCH_API_KEY|DIFFBOT_TOKEN|MOZ_ACCESS_ID|SEMRUSH_API_KEY|SERPSTAT_API_KEY|SPYFU_API_KEY|SERANKING_API_KEY|MAJESTIC_API_KEY|APOLLO_API_KEY|LUSHA_API_KEY|PDL_API_KEY|ZEROBOUNCE_API_KEY|CONTACTOUT_API_KEY|CRUNCHBASE_API_KEY|SPIDER_API_KEY|LINKUP_API_KEY|SEARCH1API_API_KEY|BRIGHT_DATA_API_TOKEN|SBR_ACCESS_TOKEN|POLYGON_API_KEY|TWELVE_DATA_API_KEY|FINNHUB_API_KEY|MARKETSTACK_API_KEY|COINGECKO_API_KEY|EODHD_API_TOKEN|TIKHUB_API_KEY|SCRAPECREATORS_API_KEY|OLOSTEP_API_KEY|PIAPI_API_KEY|MINIMAX_API_KEY|VALYU_API_KEY|GRAFANA_SERVICE_ACCOUNT_TOKEN|SHOPIFY_ADMIN_ACCESS_TOKEN|ASTRA_DB_APPLICATION_TOKEN|DEEPSEEK_REASONER_API_KEY|GOOGLE_OAUTH_ACCESS_TOKEN|BLACK_FOREST_LABS_API_KEY|CLAUDE_CODE_ACCESS_TOKEN|STABLE_DIFFUSION_API_KEY|HUGGINGFACEHUB_API_TOKEN|ALIYUN_DASHSCOPE_API_KEY|MODELSCOPE_ACCESS_TOKEN|CONFLUENT_CLOUD_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|TONGYI_QIANWEN_API_KEY|DEEPSEEK_CODER_API_KEY|QWEN_DASHSCOPE_API_KEY|DEEPSEEK_ACCESS_TOKEN|AWS_SECRET_ACCESS_KEY|MONGODB_ATLAS_API_KEY|HUGGINGFACE_API_TOKEN|DEEPSEEK_CHAT_API_KEY|SALESFORCE_SESSION_ID|ELASTIC_CLOUD_API_KEY|ANTHROPIC_OAUTH_TOKEN|DASHSCOPE_LLM_API_KEY|ALIBABA_CLOUD_API_KEY|CHATGPT_NEXT_API_KEY|SHOPIFY_ACCESS_TOKEN|DEEPSEEK_PRO_API_KEY|ALIBABACLOUD_API_KEY|AGENTSCOPE_MODEL_KEY|SPEECHMATICS_API_KEY|CLOUDFLARE_API_TOKEN|TWITTER_BEARER_TOKEN|NVIDIA_BUILD_API_KEY|ALIBABA_QWEN_API_KEY|ALIYUN_CLOUD_API_KEY|BRAVE_SEARCH_API_KEY|UPSTASH_VECTOR_TOKEN|FIREWORKS_AI_API_KEY|TWO_CAPTCHA_API_KEY|RUNWAYML_API_SECRET|DEEPSEEK_R1_API_KEY|PROMPTLAYER_API_KEY|REPLICATE_API_TOKEN|SCRAPINGBEE_API_KEY|LOBECHAT_OPENAI_KEY|AZURE_CLIENT_SECRET|ALIBABA_LLM_API_KEY|DEEPSEEK_V4_API_KEY|ALEPH_ALPHA_API_KEY|DEEPSEEK_API_SECRET|OPEN_ROUTER_API_KEY|DASHSCOPE_API_TOKEN|RUBYGEMS_AUTH_TOKEN|PAYPAL_ACCESS_TOKEN|LANGFUSE_SECRET_KEY|MAPBOX_ACCESS_TOKEN|DEEPSEEK_V3_API_KEY|DISCORD_WEBHOOK_URL|PULUMI_ACCESS_TOKEN|FIREBASE_SERVER_KEY|FIREWORKS_API_TOKEN|LANGFUSE_PUBLIC_KEY|TOGETHER_AI_API_KEY|ALIYUN_QWEN_API_KEY|ONEAPI_CHANNEL_KEY|CLAUDE_OAUTH_TOKEN|OPENROUTER_API_KEY|ELEVENLABS_API_KEY|MISTRAL_AI_API_KEY|ASSEMBLYAI_API_KEY|BRAINTRUST_API_KEY|OPENAI_PROJECT_KEY|TWOCAPTCHA_API_KEY|MODELSCOPE_API_KEY|ALIYUN_LLM_API_KEY|AGENTSCOPE_API_KEY|PERPLEXITY_API_KEY|SENDINBLUE_API_KEY|IFLYTEK_API_SECRET|MODAL_TOKEN_SECRET|OPENI_ACCESS_TOKEN|CAPMONSTER_API_KEY|BRIGHTDATA_API_KEY|NEWAPI_CHANNEL_KEY|DIGITALOCEAN_TOKEN|TWILIO_ACCOUNT_SID|HUNYUAN_SECRET_KEY|VOLCENGINE_API_KEY|NETLIFY_AUTH_TOKEN|NVIDIA_NIM_API_KEY|LANGSMITH_API_KEY|SAKANA_AI_API_KEY|CONFLUENT_API_KEY|HUNYUAN_SECRET_ID|STABILITY_API_KEY|LANGCHAIN_API_KEY|DISCORD_BOT_TOKEN|YESSOLVER_API_KEY|NEW_RELIC_API_KEY|DEEPINFRA_API_KEY|FIRECRAWL_API_KEY|SALESFORCE_SECRET|SYNTHESIA_API_KEY|REPLICATE_API_KEY|ANTHROPIC_API_KEY|TWILIO_AUTH_TOKEN|AWS_ACCESS_KEY_ID|GRAFANA_API_TOKEN|MAILCHIMP_API_KEY|HUMANLOOP_API_KEY|OKTA_CLIENT_TOKEN|DASHSCOPE_API_KEY|AZCAPTCHA_API_KEY|RUCAPTCHA_API_KEY|GOOGLE_AI_API_KEY|SAMBANOVA_API_KEY|STRIPE_SECRET_KEY|FIREWORKS_API_KEY|HUGGINGFACE_TOKEN|MISTRALAI_API_KEY|SOURCEGRAPH_TOKEN|BAILIAN_API_TOKEN|MOSTLY_AI_API_KEY|OPENWEBUI_API_KEY|OPENAI_SECRET_KEY|BYTEDANCE_API_KEY|SLACK_WEBHOOK_URL|CHATNEXT_API_KEY|SRC_ACCESS_TOKEN|SEEDANCE_API_KEY|WEBSHARE_API_KEY|BIGMODEL_API_KEY|DEEPSEEK_API_KEY|LABELBOX_API_KEY|LEPTON_API_TOKEN|EZSOLVER_API_KEY|LOBECHAT_API_KEY|DEEPGRAM_API_KEY|BAIDU_SECRET_KEY|HELICONE_API_KEY|BAICHUAN_API_KEY|PERPLEXITY_TOKEN|GOOGLE_API_TOKEN|MOONSHOT_API_KEY|MODELSCOPE_TOKEN|WEAVIATE_API_KEY|STEPIFUN_API_KEY|ALICLOUD_API_KEY|TOGETHER_API_KEY|REV_ACCESS_TOKEN|NEWRELIC_API_KEY|VOYAGEAI_API_KEY|PINECONE_API_KEY|SENDGRID_API_KEY|COINBASE_API_KEY|CLIPDROP_API_KEY|OPENROUTER_TOKEN|INTERCOM_API_KEY|LANGFUSE_API_KEY|2CAPTCHA_API_KEY|LANGFLOW_API_KEY|DOCKER_HUB_TOKEN|COMPOSIO_API_KEY|WORDWARE_API_KEY|SPARK_API_SECRET|GROQ_LLM_API_KEY|ANTHROPIC_APIKEY|LEONARDO_API_KEY|STEPFUN_API_KEY|ZHIPUAI_API_KEY|TOGETHER_AI_KEY|DATADOG_API_KEY|COINBASE_SECRET|DEEPSEEK_SECRET|NOPECHA_API_KEY|ANTHROPIC_TOKEN|FLYIO_API_TOKEN|ALIBABA_API_KEY|OPEN_ROUTER_KEY|QIANWEN_API_KEY|MAILGUN_API_KEY|SERPAPI_API_KEY|LEADERS_API_KEY|QWEN2_5_API_KEY|NEAR_AI_API_KEY|DEEPINFRA_TOKEN|PORTKEY_API_KEY|IFLYTEK_API_KEY|UPSTAGE_API_KEY|CHATGLM_API_KEY|ZENROWS_API_KEY|BASETEN_API_KEY|MINIMAX_API_KEY|MISTRAL_API_KEY|APIFY_API_TOKEN|ZEROONE_API_KEY|TWO_CAPTCHA_KEY|HUBSPOT_API_KEY|SONARQUBE_TOKEN|SLACK_BOT_TOKEN|FLOWISE_API_KEY|REPLICATE_TOKEN|STABILITY_TOKEN|FIREWORKS_TOKEN|BAILIAN_API_KEY|HUNYUAN_API_KEY|ELASTIC_API_KEY|DAYTONA_API_KEY|DASHSCOPE_TOKEN|CAPTCHA_API_KEY|DATADOG_APP_KEY|DIFY_OPENAI_KEY|FASTGPT_API_KEY|METAGPT_API_KEY|TENCENT_API_KEY|RUNWAY_API_KEY|MODAL_TOKEN_ID|ALIYUN_API_KEY|IFLYTEK_APP_ID|2CAPTCHA_TOKEN|LAMBDA_API_KEY|GOOGLE_API_KEY|NVIDIA_API_KEY|HEROKU_API_KEY|DIFY_MODEL_KEY|SAKANA_API_KEY|CAPMONSTER_KEY|BIGMODEL_TOKEN|OPENROUTER_KEY|FAL_AI_API_KEY|NOTION_API_KEY|FASTLY_API_KEY|RESEND_API_KEY|NEARAI_API_KEY|SERPER_API_KEY|TONGYI_API_KEY|NOVITA_API_KEY|GEMINI_API_KEY|LEPTON_API_KEY|SESSION_SECRET|CREWAI_API_KEY|TAVILY_API_KEY|DEEPSEEK_TOKEN|GRETEL_API_KEY|COHERE_API_KEY|GLADIA_API_KEY|CLAUDE_API_KEY|OPENAI_API_KEY|RUNPOD_API_KEY|VOYAGE_API_KEY|LINODE_API_KEY|HEYGEN_API_KEY|OKTA_API_TOKEN|PERPLEXITY_KEY|DOUBAO_API_KEY|QDRANT_API_KEY|MAILCHIMP_KEY|FLY_API_TOKEN|BREVO_API_KEY|BAIDU_API_KEY|SPARK_API_KEY|OPENWEBUI_KEY|GRAFANA_TOKEN|STABILITY_KEY|DISCORD_TOKEN|WANDB_API_KEY|ARK_API_TOKEN|NETLIFY_TOKEN|ANTHROPIC_KEY|MISTRAL_TOKEN|REPLICATE_KEY|ZHIPU_API_KEY|VULTR_API_KEY|DASHSCOPE_KEY|BRAVE_API_KEY|FIREWORKS_KEY|MAXKB_API_KEY|OPENI_API_KEY|HF_API_TOKEN|TOGETHER_KEY|FISH_API_KEY|GROQ_API_KEY|PIKA_API_KEY|CF_API_TOKEN|SUNO_API_KEY|MAPBOX_TOKEN|COZE_BOT_KEY|NOTION_TOKEN|COZE_API_KEY|VERCEL_TOKEN|SOAX_API_KEY|BIGMODEL_KEY|DIFY_API_KEY|2CAPTCHA_KEY|FUGU_API_KEY|NEON_API_KEY|GITHUB_TOKEN|PPLX_API_KEY|LUMA_API_KEY|DEEPSEEK_KEY|Z_AI_API_KEY|LINODE_TOKEN|GLM5_API_KEY|GLM4_API_KEY|OPENAI_TOKEN|01AI_API_KEY|AI21_API_KEY|QWEN_API_KEY|KIMI_API_KEY|JINA_API_KEY|SERPAPI_KEY|XAI_API_KEY|FASTGPT_KEY|ONE_API_KEY|ZAI_API_KEY|GCP_API_KEY|CHATGLM_KEY|SONAR_TOKEN|N8N_API_KEY|ASTRA_TOKEN|MISTRAL_KEY|NIM_API_KEY|GLM_API_KEY|ZHIPUAI_KEY|ARK_API_KEY|BFL_API_KEY|MODAL_TOKEN|ALI_API_KEY|FAL_API_KEY|EXA_API_KEY|APIFY_TOKEN|CAPTCHA_KEY|NR_API_KEY|DS_API_KEY|NVIDIA_KEY|JWT_SECRET|QWEN_TOKEN|CLAUDE_KEY|OR_API_KEY|GROQ_TOKEN|OPENAI_KEY|SOAX_TOKEN|SAKANA_KEY|QIANFAN_AK|OPENROUTER|QIANFAN_SK|PYPI_TOKEN|YI_API_KEY|XI_API_KEY|NVIDIA_NIM|ZHIPU_KEY|NPM_TOKEN|DO_TOKEN|QWEN_KEY|PPLX_KEY|Z_AI_KEY|HF_TOKEN|OR_TOKEN|FAL_KEY|ZAI_KEY)\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{20,200})["']?"#).unwrap(), 1), // ENV_MAP 362
            (
                KeyKind::Generic,
                Regex::new(
                    r#"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|token)\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{24,120})["']?"#,
                )
                .unwrap(),
                1,
            ),
            // DashScope / Alibaba family. Suffix set is widened to
            // _API_KEY|_API_TOKEN|_TOKEN|_KEY because the same keys ship as
            // BAILIAN_API_KEY, MODELSCOPE_TOKEN, TONGYI_QIANWEN_API_KEY, …
            (
                KeyKind::Generic,
                Regex::new(
                    r#"(?i)\b(?:DASHSCOPE|DASHSCOPE_LLM|ALIBABA_CLOUD|ALIBABA|ALIYUN|ALICLOUD|ALIYUN_LLM|BAILIAN|QWEN|QWEN_DASHSCOPE|TONGYI_QIANWEN|QIANWEN|ALIYUN_QWEN|ALIBABA_QWEN|MODELSCOPE)(?:_API_KEY|_API_TOKEN|_TOKEN|_KEY)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,200})"#,
                )
                .unwrap(),
                1,
            ),
            // Chinese AI providers that share the same repo/commit space as
            // DashScope keys — ported verbatim from key_patterns.py ENV_RE.
            (
                KeyKind::Generic,
                Regex::new(
                    r#"(?i)\b(?:ZHIPU|ZHIPUAI|Z_AI|ZAI|GLM|CHATGLM|BIGMODEL|KIMI|MOONSHOT|DEEPSEEK|DS_API|SILICONFLOW|MINIMAX|BAICHUAN|SENSENOVA|HUNYUAN|SPARK|ERNIE|WENXIN|INTERNLM|YI_API|STEPFUN|STEP_API|NOVITA|CEREBRAS|DEEPINFRA|VOYAGE|JINA|SGLANG|MISTRAL|COHERE|TOGETHER|FIREWORKS|PERPLEXITY|PPLX|GROQ)(?:_API_KEY|_API_TOKEN|_TOKEN|_KEY)\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{20,200})"#,
                )
                .unwrap(),
                1,
            ),
        ],
    })
}

/// Kubernetes Secret manifests, CI variables and `.env` dumps sometimes store
/// a PAT as base64 rather than plain text. Decode only base64-shaped runs and
/// accept the result only when it contains a credible PAT; this keeps the
/// extra coverage from turning every base64 blob into a candidate.
fn base64_pat_candidates(line: &str) -> Vec<String> {
    static B64: OnceLock<Regex> = OnceLock::new();
    static PAT: OnceLock<Regex> = OnceLock::new();
    let b64 = B64.get_or_init(|| Regex::new(r"\b[A-Za-z0-9+/_-]{40,800}={0,2}").unwrap());
    let pat = PAT.get_or_init(|| {
        Regex::new(
            r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,200}|(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b",
        )
        .unwrap()
    });
    let mut out = Vec::new();
    for m in b64.find_iter(line) {
        let raw = m.as_str();
        let Ok(bytes) = base64::engine::general_purpose::STANDARD
            .decode(raw)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(raw))
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw))
        else {
            continue;
        };
        let Ok(decoded) = String::from_utf8(bytes) else {
            continue;
        };
        for cap in pat.captures_iter(&decoded) {
            if let Some(k) = cap.get(0) {
                let key = k.as_str().to_string();
                if credible_github_pat(&key) && !out.contains(&key) {
                    out.push(key);
                }
            }
        }
    }
    out
}

/// Extraction used for snippets, commits and patch hunks: no provider hints,
/// because the surrounding file already supplies the endpoint.
pub fn extract(text: &str) -> Extraction {
    extract_impl(text, false)
}

/// Extraction for whole files / documents: when a file carries no endpoint at
/// all, a key found under a provider env var gets the provider's official
/// endpoint so it can still be probed.
pub fn extract_hinted(text: &str) -> Extraction {
    extract_impl(text, true)
}

fn extract_impl(text: &str, hints: bool) -> Extraction {
    let p = patterns();
    let lines: Vec<&str> = text.lines().collect();
    let mut endpoints: Vec<EndpointHit> = Vec::new();
    let mut keys: Vec<KeyHit> = Vec::new();
    let mut seen_endpoints: HashSet<(usize, String)> = HashSet::new();
    let mut seen_keys: HashSet<String> = HashSet::new();

    for (idx, line) in lines.iter().enumerate() {
        let mut raw_candidates: Vec<(String, bool)> = Vec::new();

        for cap in p.assign.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                raw_candidates.push((m.as_str().to_string(), true));
            }
        }
        for m in p.url.find_iter(line) {
            raw_candidates.push((m.as_str().to_string(), false));
        }
        for m in p.bare.find_iter(line) {
            raw_candidates.push((m.as_str().to_string(), false));
        }

        for (raw, assigned) in raw_candidates {
            if let Some(url) = normalize(&raw) {
                if is_groq_endpoint(&url) {
                    continue;
                }
                let strong = assigned || raw.to_lowercase().contains("/v1") || api_like_host(&url);
                if seen_endpoints.insert((idx, url.clone())) {
                    endpoints.push(EndpointHit {
                        line: idx,
                        url,
                        strong,
                    });
                }
            }
        }

        for (kind, re, group) in &p.keys {
            for cap in re.captures_iter(line) {
                let Some(m) = cap.get(*group) else { continue };
                let key = m.as_str().to_string();
                if key.starts_with("sk_live_") || key.starts_with("sk_test_") {
                    // Stripe secret keys, not OpenAI: OpenAI uses sk-live- with a hyphen.
                    continue;
                }
                if *kind == KeyKind::Generic
                    && (key.starts_with("ghp_")
                        || key.starts_with("github_pat_")
                        || key.starts_with("gho_")
                        || key.starts_with("ghu_")
                        || key.starts_with("ghs_")
                        || key.starts_with("ghr_")
                        // Groq is retired. A bare gsk_ value must not become a
                        // Generic key and pair with an unrelated relay URL.
                        || key.starts_with("gsk_"))
                {
                    continue;
                }
                // A ported pattern with a loose value class can capture a URL
                // (e.g. the BASE_URL env row). A URL is never a key.
                if key.contains("://") || key.starts_with("http") {
                    continue;
                }
                if looks_placeholder(&key) {
                    continue;
                }
                if *kind == KeyKind::GithubPat && !credible_github_pat(&key) {
                    continue;
                }
                if seen_keys.insert(key.clone()) {
                    keys.push(KeyHit {
                        line: idx,
                        key,
                        kind: *kind,
                    });
                }
            }
        }
        for key in base64_pat_candidates(line) {
            if seen_keys.insert(key.clone()) {
                keys.push(KeyHit {
                    line: idx,
                    key,
                    kind: KeyKind::GithubPat,
                });
            }
        }
    }

    // Keys found under a provider env var often have no URL on the line.
    // Attach the provider's official endpoint only when the line has no
    // endpoint of its own, so an explicit host always wins.
    if hints && endpoints.is_empty() {
        let mut injected: Vec<EndpointHit> = Vec::new();
        for key in &keys {
            if key.kind == KeyKind::DashScopeWorkspace {
                continue;
            }
            // An explicit endpoint anywhere near the key (a BASE_URL two
            // lines below, a relay host in the same block) always wins over
            // the provider default.
            if endpoints
                .iter()
                .any(|e| e.line.abs_diff(key.line) <= 5)
            {
                continue;
            }
            let Some(line) = lines.get(key.line) else { continue };
            if let Some(ep) = provider_hint(line) {
                if seen_endpoints.insert((key.line, ep.to_string())) {
                    injected.push(EndpointHit {
                        line: key.line,
                        url: ep.to_string(),
                        strong: true,
                    });
                }
            }
        }
        endpoints.extend(injected);
    }

    // A classic DashScope key looks like a generic `sk-<32hex>` token. Label
    // it as DashScope only when the surrounding file has DashScope context;
    // arbitrary relay/OpenAI-shaped keys must keep their original kind.
    let dash_eps: Vec<&EndpointHit> = endpoints
        .iter()
        .filter(|e| is_dashscope_endpoint(&e.url))
        .collect();
    for key in &mut keys {
        if key.kind != KeyKind::OpenAi && key.kind != KeyKind::Generic {
            continue;
        }
        if !is_quality_dashscope_key(&key.key) {
            continue;
        }
        let line_ctx = lines
            .get(key.line)
            .is_some_and(|line| dashscope_context_line(line));
        let dash_dist = dash_eps.iter().map(|ep| key.line.abs_diff(ep.line)).min();
        let other_dist = endpoints
            .iter()
            .filter(|ep| !is_dashscope_endpoint(&ep.url))
            .map(|ep| key.line.abs_diff(ep.line))
            .min();
        if line_ctx || dash_dist.is_some_and(|d| d <= 80 && d < other_dist.unwrap_or(usize::MAX)) {
            key.kind = KeyKind::DashScope;
        }
    }

    // TTS providers often use bare 32-char tokens or `sk_` values without a
    // distinctive model prefix. Classify them from the surrounding file, so
    // the prober can route them to the TTS endpoint instead of chat models.
    for key in &mut keys {
        if !matches!(
            key.kind,
            KeyKind::Generic | KeyKind::OpenAi | KeyKind::HuggingFace
        ) {
            continue;
        }
        let ctx = lines
            .get(key.line)
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if ctx.contains("fish.audio")
            || ctx.contains("fish_api_key")
            || ctx.contains("fish_audio")
            || ctx.contains("fishaudio")
        {
            key.kind = KeyKind::FishAudio;
        } else if ctx.contains("elevenlabs")
            || ctx.contains("eleven_labs")
            || ctx.contains("xi-api-key")
            || ctx.contains("elevenlabs_api_key")
        {
            key.kind = KeyKind::ElevenLabs;
        } else if ctx.contains("seedance")
            || ctx.contains("ark_api_key")
            || ctx.contains("ark_api")
            || ctx.contains("ark.cn-beijing")
            || ctx.contains("volces.com")
        {
            key.kind = KeyKind::Seedance;
        }
    }

    let mut pairs: Vec<PairHit> = Vec::new();
    let mut seen_pairs: HashSet<(String, String)> = HashSet::new();

    for key in &keys {
        let mut best: Option<(&EndpointHit, usize)> = None;
        for ep in &endpoints {
            let dist = key.line.abs_diff(ep.line);
            if dist > 80 {
                continue;
            }
            if !ep.strong && dist > 12 {
                continue;
            }
            if !endpoint_fits_ex(key.kind, &ep.url, ep.strong) {
                continue;
            }
            let better = match best {
                None => true,
                Some((_, bd)) => dist < bd,
            };
            if better {
                best = Some((ep, dist));
            }
        }
        if let Some((ep, dist)) = best {
            if seen_pairs.insert((ep.url.clone(), key.key.clone())) {
                pairs.push(PairHit {
                    endpoint: ep.url.clone(),
                    key: key.key.clone(),
                    kind: key.kind,
                    line: key.line,
                    distance: dist,
                });
            }
        }
    }

    Extraction {
        pairs,
        endpoints,
        keys,
    }
}

pub fn opaque_tokens(text: &str) -> Vec<(usize, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40,64}\b").unwrap());
    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        for m in re.find_iter(line) {
            let tok = m.as_str();
            if !tok.chars().any(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            if looks_placeholder(tok) {
                continue;
            }
            out.push((idx, tok.to_string()));
        }
    }
    out
}

pub fn normalize(raw: &str) -> Option<String> {
    let mut s = raw
        .trim()
        .trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '`' | ',' | ';' | ')' | ']' | '}' | '(' | '[' | '{'
            )
        })
        .to_string();
    if s.is_empty() {
        return None;
    }
    if !s.starts_with("http://") && !s.starts_with("https://") {
        s = format!("https://{}", s);
    }
    let u = reqwest::Url::parse(&s).ok()?;
    let host = u.host_str()?.to_lowercase();
    if !host.contains('.') || is_denied(&host) || generic_tld(&host) || private_ip_host(&host) {
        return None;
    }
    let path = u.path().trim_end_matches('/');
    let lp = path.to_ascii_lowercase();
    for ext in [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".mp4",
        ".webp", ".pdf", ".zip", ".gz", ".js.map",
    ] {
        if lp.ends_with(ext) {
            return None;
        }
    }
    let keep = if lp.ends_with("/v1") || lp.ends_with("/v1beta") {
        path.to_string()
    } else if let Some(i) = lp.find("/v1/") {
        path[..i + 3].to_string()
    } else {
        String::new()
    };
    let port = u.port().map(|p| format!(":{}", p)).unwrap_or_default();
    Some(format!("{}://{}{}{}", u.scheme(), host, port, keep))
}

pub fn host_of(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
        .unwrap_or_else(|| url.to_string())
}

/// Alibaba Cloud Model Studio (DashScope) workspace endpoints look like
/// `ws-<id>.<region>.maas.aliyuncs.com/compatible-mode/v1`.
/// Groq was explicitly removed from the product; old source pages and DB
/// rows must not re-introduce it through endpoint pivots or probes.
pub fn is_groq_endpoint(url: &str) -> bool {
    let host = host_of(url);
    host == "api.groq.com" || host.ends_with(".api.groq.com")
}

pub fn is_dashscope_workspace_endpoint(url: &str) -> bool {
    let host = host_of(url);
    host.ends_with(".maas.aliyuncs.com")
        || (host.starts_with("ws-") && host.contains("aliyuncs.com"))
}

pub fn is_dashscope_workspace_key(key: &str) -> bool {
    key.starts_with("sk-ws-")
}

/// Classic DashScope API keys are exactly `sk-` plus 32 hexadecimal chars.
/// Workspace keys (`sk-ws-…`) and arbitrary relay `sk-` values deliberately do
/// not match this quality predicate.
pub fn is_quality_dashscope_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    if lower.len() != 35 || !lower.starts_with("sk-") {
        return false;
    }
    let body = &lower[3..];
    if !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let uniq: HashSet<u8> = body.bytes().collect();
    uniq.len() >= 10
}

/// DashScope API endpoints only. `aliyuncs.com` alone is too broad: OSS, SLS
/// and other Alibaba services share the domain.
pub fn is_dashscope_endpoint(url: &str) -> bool {
    let host = host_of(url);
    if host.contains("dashscope") && !host.contains("console") {
        return true;
    }
    is_dashscope_workspace_endpoint(url)
}

/// Environment-variable → provider endpoint hints (ported from the v12
/// catalog's VALIDATION_META). Without these a key found as `ZAI_API_KEY=…`
/// has no endpoint to pair with and never reaches the prober.
fn provider_hint(line: &str) -> Option<&'static str> {
    let up = line.to_ascii_uppercase();
    let table: &[(&str, &str)] = &[
        ("DASHSCOPE", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        ("BAILIAN", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        ("QWEN", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        ("MODELSCOPE", "https://api-inference.modelscope.cn/v1"),
        ("ZHIPU", "https://open.bigmodel.cn/api/paas/v4"),
        ("Z_AI", "https://api.z.ai/api/paas/v4"),
        ("ZAI", "https://api.z.ai/api/paas/v4"),
        ("BIGMODEL", "https://open.bigmodel.cn/api/paas/v4"),
        ("GLM", "https://open.bigmodel.cn/api/paas/v4"),
        ("KIMI", "https://api.moonshot.cn/v1"),
        ("MOONSHOT", "https://api.moonshot.cn/v1"),
        ("SILICONFLOW", "https://api.siliconflow.cn/v1"),
        ("MINIMAX", "https://api.minimax.chat/v1"),
        ("STEPFUN", "https://api.stepfun.com/v1"),
        ("BAICHUAN", "https://api.baichuan-ai.com/v1"),
        ("DEEPSEEK", "https://api.deepseek.com/v1"),
        ("OPENROUTER", "https://openrouter.ai/api/v1"),
        ("TOGETHER", "https://api.together.xyz/v1"),
        ("FIREWORKS", "https://api.fireworks.ai/inference/v1"),
        ("CEREBRAS", "https://api.cerebras.ai/v1"),
        ("DEEPINFRA", "https://api.deepinfra.com/v1/openai"),
        ("NOVITA", "https://api.novita.ai/v3/openai"),
        ("MISTRAL", "https://api.mistral.ai/v1"),
        ("COHERE", "https://api.cohere.ai"),
        ("PERPLEXITY", "https://api.perplexity.ai"),
        ("PPLX", "https://api.perplexity.ai"),
        ("GROQ", "https://api.groq.com/openai/v1"),
        ("XAI", "https://api.x.ai/v1"),
        ("ANTHROPIC", "https://api.anthropic.com"),
        ("OPENAI", "https://api.openai.com/v1"),
        ("GEMINI", "https://generativelanguage.googleapis.com/v1beta"),
        ("GOOGLE", "https://generativelanguage.googleapis.com/v1beta"),
        ("HUGGINGFACE", "https://router.huggingface.co/v1"),
        ("NVIDIA", "https://integrate.api.nvidia.com/v1"),
        ("NIM", "https://integrate.api.nvidia.com/v1"),
        ("REPLICATE", "https://api.replicate.com/v1"),
        ("ELEVENLABS", "https://api.elevenlabs.io/v1"),
    ];
    for (needle, url) in table {
        if up.contains(needle) {
            return Some(url);
        }
    }
    None
}

fn dashscope_context_line(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.contains("dashscope")
        || l.contains("bailian")
        || l.contains("qwen_api_key")
        || l.contains("百炼")
        // Env/var family ported from key_patterns.py: a key under any of these
        // names is a DashScope/Alibaba key even without an endpoint nearby.
        || l.contains("modelscope")
        || l.contains("tongyi")
        || l.contains("qianwen")
        || l.contains("aliyun")
        || l.contains("alicloud")
        || l.contains("alibaba_cloud")
        || l.contains("通义")
        || l.contains("千问")
}

/// Official first-party API hosts (not relays). Used only for ranking:
/// official keys get a small priority edge over DashScope, and only slightly.
pub fn is_official_endpoint(url: &str) -> bool {
    let host = host_of(url);
    [
        "api.openai.com",
        "api.anthropic.com",
        "api.deepseek.com",
        "openrouter.ai",
        "api.moonshot.cn",
        "api.moonshot.ai",
        "api.x.ai",
        "generativelanguage.googleapis.com",
        "api.mistral.ai",
        "api.together.xyz",
        "api.fireworks.ai",
        "api.cohere.ai",
        "api.perplexity.ai",
        "api.cerebras.ai",
        "api.sambanova.ai",
        "api.novita.ai",
        "api.deepinfra.com",
        "api.nvidia.com",
        "integrate.api.nvidia.com",
        "router.huggingface.co",
        "api.replicate.com",
        "api.ai21.com",
        "api.cloudflare.com",
    ]
    .iter()
    .any(|official| host == *official || host.ends_with(&format!(".{}", official)))
}

/// Priority subset: OpenAI, Anthropic, DeepSeek, OpenRouter,
/// Moonshot and xAI only. Other first-party hosts are still scanned, but
/// deliberately not promoted above DashScope.
pub fn is_priority_official_endpoint(url: &str) -> bool {
    let host = host_of(url);
    [
        "api.openai.com",
        "api.anthropic.com",
        "api.deepseek.com",
        "openrouter.ai",
        "api.moonshot.cn",
        "api.moonshot.ai",
        "api.x.ai",
    ]
    .iter()
    .any(|official| host == *official || host.ends_with(&format!(".{}", official)))
}

fn api_like_host(url: &str) -> bool {
    let host = host_of(url);
    host.starts_with("api.")
        || host.starts_with("api-")
        || host.contains("api.")
        || host.contains("gateway")
        || host.contains("relay")
        || host.contains("llm")
        || host.contains("openai")
        || host.contains("anthropic")
        || host.contains("dashscope")
        || is_dashscope_workspace_endpoint(url)
        || is_official_endpoint(url)
        || host.contains("chat")
        || host.starts_with("ai.")
        || host.contains(".ai.")
}

pub fn endpoint_fits(kind: KeyKind, endpoint: &str) -> bool {
    endpoint_fits_ex(kind, endpoint, false)
}

fn endpoint_fits_ex(kind: KeyKind, endpoint: &str, assigned: bool) -> bool {
    let host = host_of(endpoint);
    let relayish = host.starts_with("api.")
        || host.contains("api.")
        || host.contains("relay")
        || host.contains("gateway")
        || host.contains("llm")
        || host.contains("openai")
        || host.contains("dashscope")
        || is_dashscope_workspace_endpoint(endpoint)
        || endpoint.contains("/v1");
    // OpenRouter's official host is not a generic relay: a 32-char MD5/hash or
    // an OpenAI key paired with it is always a false positive. Only a real
    // `sk-or-v1-…` credential belongs to this endpoint.
    if host == "openrouter.ai" || host == "www.openrouter.ai" {
        return kind == KeyKind::OpenRouter;
    }
    match kind {
        KeyKind::HuggingFace => host.contains("huggingface") || host == "hf.co",
        KeyKind::FishAudio => host.contains("fish.audio") || assigned,
        KeyKind::ElevenLabs => host.contains("elevenlabs.io") || assigned,
        KeyKind::Seedance => {
            host.contains("seedance")
                || host.contains("volces.com")
                || host.contains("bytepluses.com")
                || assigned
        }
        KeyKind::Google => host.contains("googleapis"),
        KeyKind::OpenRouter => host.contains("openrouter"),
        KeyKind::GithubPat => host == "api.github.com",
        KeyKind::Xai => host.contains("x.ai") || host.contains("xai"),
        KeyKind::Anthropic => {
            host.contains("anthropic") || host.contains("claude") || relayish || assigned
        }
        KeyKind::OpenAi => relayish || assigned,
        KeyKind::DashScope => host.contains("dashscope") || host.contains("aliyuncs") || assigned,
        KeyKind::DashScopeWorkspace => {
            is_dashscope_workspace_endpoint(endpoint) || host.contains("dashscope") || assigned
        }
        KeyKind::Generic => {
            host.contains("relay")
                || host.contains("gateway")
                || host.contains("llm")
                || host.contains("openai")
                || host.contains("dashscope")
                || is_dashscope_workspace_endpoint(endpoint)
                || is_official_endpoint(endpoint)
                || endpoint.contains("/v1")
        }
    }
}

fn generic_tld(host: &str) -> bool {
    // Only unambiguous noise TLDs seen in documentation/package hosts.
    // Do not block real API domains such as api.relay.tech or api.cloud.
    const GENERIC: &[&str] = &["page", "store", "host", "world"];
    let tld = host.rsplit('.').next().unwrap_or("");
    GENERIC.contains(&tld)
}

fn private_ip_host(host: &str) -> bool {
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast();
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

fn is_denied(host: &str) -> bool {
    const DENY: &[&str] = &[
        "github.com",
        "githubusercontent.com",
        "github.io",
        "gh.io",
        "bingparachute.com",
        "lp-note.com",
        "githubassets.com",
        "gitlab.com",
        "bitbucket.org",
        "npmjs.com",
        "npmjs.org",
        "pypi.org",
        "crates.io",
        "rust-lang.org",
        "docs.rs",
        "shields.io",
        "img.shields.io",
        "badgen.net",
        "stackoverflow.com",
        "stackexchange.com",
        "medium.com",
        "youtube.com",
        "youtu.be",
        "twitter.com",
        "x.com",
        "discord.com",
        "discord.gg",
        "t.me",
        "telegram.org",
        "wikipedia.org",
        "w3.org",
        "schema.org",
        "json-schema.org",
        "example.com",
        "example.org",
        "example.net",
        "localhost",
        "claude.ai",
        "platform.openai.com",
        "console.anthropic.com",
        "docs.anthropic.com",
        "k8s.io",
        "kubernetes.io",
        "nodejs.org",
        "python.org",
        "golang.org",
        "docker.io",
        "docker.com",
        "maven.org",
        "gradle.org",
        "istio.io",
        "helm.sh",
        "openshift.io",
        "apache.org",
        "test.com",
        "provider.com",
        "domain.com",
        "your-domain.com",
        "supabase.co",
    ];
    for d in DENY {
        if host == *d || host.ends_with(&format!(".{}", d)) {
            return true;
        }
    }
    if host == "openai.com" || host == "www.openai.com" || host == "help.openai.com" {
        return true;
    }
    if host == "anthropic.com" || host == "www.anthropic.com" || host == "support.anthropic.com" {
        return true;
    }
    if host.starts_with("127.")
        || host.starts_with("192.168.")
        || host.starts_with("10.")
        || host.starts_with("172.16.")
        || host.starts_with("172.17.")
        || host.starts_with("172.18.")
        || host.starts_with("172.19.")
        || host.starts_with("172.2")
        || host.starts_with("172.30.")
        || host.starts_with("172.31.")
        || host == "0.0.0.0"
    {
        return true;
    }
    if host.starts_with("docs.")
        || host.starts_with("help.")
        || host.starts_with("support.")
        || host.starts_with("status.")
    {
        return true;
    }
    false
}

/// GitHub code search is full of test fixtures, redacted examples and
/// obvious dummy tokens. A real PAT has a high-entropy random body; reject
/// the low-effort values before they consume a probe.
fn credible_github_pat(k: &str) -> bool {
    let lower = k.to_ascii_lowercase();
    if !(lower.starts_with("ghp_")
        || lower.starts_with("github_pat_")
        || lower.starts_with("gho_")
        || lower.starts_with("ghu_")
        || lower.starts_with("ghs_")
        || lower.starts_with("ghr_"))
    {
        return false;
    }
    let body = lower
        .strip_prefix("github_pat_")
        .or_else(|| lower.strip_prefix("ghp_"))
        .or_else(|| lower.strip_prefix("gho_"))
        .or_else(|| lower.strip_prefix("ghu_"))
        .or_else(|| lower.strip_prefix("ghs_"))
        .or_else(|| lower.strip_prefix("ghr_"))
        .unwrap_or("");
    if body.len() < 20 || body.chars().filter(|c| c.is_ascii_alphanumeric()).count() < 20 {
        return false;
    }
    for p in [
        "1234567890",
        "123456789",
        "0123456789",
        "abcdefghij",
        "xxxxxxxx",
        "yyyyyyyy",
        "your_",
        "your-",
        "token_here",
        "token-here",
        "example",
        "placeholder",
        "redacted",
        "fake",
        "dummy",
        "test",
        "sample",
        "changeme",
    ] {
        if lower.contains(p) {
            return false;
        }
    }
    let mut counts = [0usize; 36];
    let mut n = 0usize;
    for c in body.bytes() {
        let idx = match c {
            b'0'..=b'9' => (c - b'0') as usize,
            b'a'..=b'z' => 10 + (c - b'a') as usize,
            b'A'..=b'Z' => 10 + (c - b'A') as usize,
            _ => continue,
        };
        counts[idx] += 1;
        n += 1;
    }
    if n < 20 {
        return false;
    }
    let mut entropy = 0.0f64;
    for c in counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n as f64;
        entropy -= p * p.log2();
    }
    entropy >= 3.0
}

fn looks_placeholder(k: &str) -> bool {
    if k.len() < 20 {
        return true;
    }
    let lower = k.to_lowercase();
    for p in [
        "your",
        "example",
        "xxxx",
        "placeholder",
        "changeme",
        "change_me",
        "dummy",
        "redacted",
        "insert_",
        "replace_",
        "sample",
        "fake",
        "sk-test",
        "sk-test-",
        "test-key",
        "test_key",
        "api_key_here",
        "todo",
        "<",
        ">",
        "${",
        "{{",
        "process.env",
        "os.environ",
        "***",
        "...",
        "…",
    ] {
        if lower.contains(p) {
            return true;
        }
    }
    let uniq: HashSet<char> = lower.chars().filter(|c| c.is_alphanumeric()).collect();
    uniq.len() < 8
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
# config
OPENAI_BASE_URL = "https://api.aicredits.in/v1"
OPENAI_API_KEY=sk-live-cb5d8ff6563ab452b8dca1ce5f38cdb4827ff06f7a455190280f3f3713e5e5a8
"#;

    #[test]
    fn opaque_hex_tokens_are_found() {
        let txt = "relay https://api.example.test/v1\nkey 1e577a1869dcc432d4e482d89c7db1b2";
        let toks = opaque_tokens(txt);
        assert_eq!(toks.len(), 1);
        assert_eq!(toks[0].1, "1e577a1869dcc432d4e482d89c7db1b2");
        assert!(opaque_tokens("sha 01234567890123456789012345678901").is_empty());
    }

    #[test]
    fn generic_tlds_are_not_endpoints() {
        assert!(normalize("https://pagination.page").is_none());
        assert!(normalize("https://api.app.state.store").is_none());
        assert!(normalize("https://relay.mycorp.com/v1").is_some());
    }

    #[test]
    fn openrouter_keys_accept_uppercase_and_are_not_generic() {
        let key = format!("sk-or-v1-{}", "A1b2".repeat(16));
        let txt =
            format!("OPENROUTER_API_KEY={key}\nOPENROUTER_BASE_URL=https://openrouter.ai/api/v1");
        let ex = extract(&txt);
        assert_eq!(ex.pairs.len(), 1, "pairs: {:?}", ex.pairs);
        assert_eq!(ex.pairs[0].kind, KeyKind::OpenRouter);
        assert_eq!(ex.pairs[0].key, key);
        assert!(!endpoint_fits(KeyKind::Generic, &ex.pairs[0].endpoint));
    }

    #[test]
    fn quality_dashscope_classic_key_is_reclassified() {
        let txt = r#"
DASHSCOPE_API_KEY=sk-9f4c2a7b1e8d3c6a0b5d9e2f7a1c4b8d
DASHSCOPE_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
"#;
        let ex = extract(txt);
        assert_eq!(ex.pairs.len(), 1, "pairs: {:?}", ex.pairs);
        assert_eq!(ex.pairs[0].kind, KeyKind::DashScope);
        assert!(is_quality_dashscope_key(&ex.pairs[0].key));
    }

    #[test]
    fn workspace_keys_are_not_quality_dashscope() {
        let ws = "sk-ws-H1234567890abcdefghijklmnopqrstuv";
        assert!(!is_quality_dashscope_key(ws));
        let txt = format!(
            "DASHSCOPE_API_KEY={ws}\nDASHSCOPE_BASE_URL=https://ws-bvicalcqq28azivp.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"
        );
        let ex = extract(&txt);
        assert_eq!(ex.pairs.len(), 1, "pairs: {:?}", ex.pairs);
        assert_eq!(ex.pairs[0].kind, KeyKind::DashScopeWorkspace);
    }

    #[test]
    fn classic_dashscope_shape_needs_dashscope_context() {
        let key = "sk-9f4c2a7b1e8d3c6a0b5d9e2f7a1c4b8d";
        let txt = format!("OPENAI_API_KEY={key}\nhttps://api.openai.com/v1");
        let ex = extract(&txt);
        assert_eq!(ex.pairs.len(), 1, "pairs: {:?}", ex.pairs);
        assert_eq!(ex.pairs[0].kind, KeyKind::OpenAi);
        assert!(is_quality_dashscope_key(key));
    }

    #[test]
    fn dashscope_ws_key_with_dots_is_extracted() {
        let txt = r#"
DASHSCOPE_API_KEY=sk-ws-AbCdEf.1234567890_AbCdEfGhIjKl.MnOpQrStUvWxYz0123456789
DASHSCOPE_BASE_URL=https://ws-bvicalcqq28azivp.cn-beijing.maas.aliyuncs.com/compatible-mode/v1
"#;
        let ex = extract(txt);
        assert_eq!(ex.keys.len(), 1, "keys: {:?}", ex.keys);
        assert!(ex.keys[0].key.starts_with("sk-ws-"));
        assert_eq!(ex.pairs.len(), 1, "pairs: {:?}", ex.pairs);
        assert!(is_dashscope_workspace_endpoint(&ex.pairs[0].endpoint));
    }

    #[test]
    fn github_pat_keys_are_classified() {
        let txt = r#"
GITHUB_TOKEN=ghp_Q7mK2vR9xT4zL8pN6cB3wH5sD0gJ2aY7uE1f
GH_TOKEN=github_pat_9fK2mQ7vR4xT8zL1pN6cB3wH5sD0gJ2aY7uE1fQ7mK2vR9xT4zL8pN6cB3wH5
GITHUB_TOKEN=ghp_123456789012345678901234567890123456
"#;
        let ex = extract(txt);
        assert!(ex.keys.iter().any(|k| k.kind == KeyKind::GithubPat));
        assert!(ex.keys.iter().any(|k| k.key.starts_with("ghp_")));
        assert!(ex.keys.iter().any(|k| k.key.starts_with("github_pat_")));
        assert!(!ex
            .keys
            .iter()
            .any(|k| k.key == "ghp_123456789012345678901234567890123456"));
    }

    #[test]
    fn official_deepseek_key_pairs_with_generic_endpoint() {
        let txt = format!(r#"
DEEPSEEK_API_KEY=sk-{}"
https://api.deepseek.com
"#, "0123456789abcdef0123456789abcdef");
        let ex = extract(&txt);
        assert!(!ex.keys.is_empty(), "keys: {:?}", ex.keys);
        assert!(
            ex.pairs
                .iter()
                .any(|p| p.endpoint.contains("api.deepseek.com")),
            "pairs: {:?}",
            ex.pairs
        );
        assert!(is_official_endpoint("https://api.deepseek.com"));
        assert!(is_priority_official_endpoint("https://api.deepseek.com"));
        assert!(!is_priority_official_endpoint("https://api.mistral.ai/v1"));
        assert!(!is_priority_official_endpoint(
            "https://generativelanguage.googleapis.com"
        ));
        assert!(!is_priority_official_endpoint("https://api.cohere.ai"));
        assert!(!is_priority_official_endpoint(
            "https://router.huggingface.co/v1"
        ));
    }

    #[test]
    fn dashscope_native_key_pairs_with_compatible_endpoint() {
        let txt = r#"
DASHSCOPE_API_KEY=abcdefghijklmnopqrstuvwxyz123456
DASHSCOPE_BASE_URL=https://dashscope.aliyuncs.com/api/v1
"#;
        let ex = extract(txt);
        assert!(!ex.keys.is_empty(), "keys: {:?}", ex.keys);
        assert_eq!(ex.pairs.len(), 1, "pairs: {:?}", ex.pairs);
        assert!(ex.pairs[0].endpoint.contains("dashscope"));
        assert!(endpoint_fits(KeyKind::Generic, &ex.pairs[0].endpoint));
    }

    #[test]
    fn pairs_endpoint_with_key() {
        let ex = extract(SAMPLE);
        assert_eq!(ex.pairs.len(), 1, "pairs: {:?}", ex.pairs);
        assert_eq!(ex.pairs[0].endpoint, "https://api.aicredits.in/v1");
        assert!(ex.pairs[0].key.starts_with("sk-live-"));
        assert_eq!(ex.pairs[0].kind, KeyKind::OpenAi);
    }

    #[test]
    fn dashscope_key_pairs_with_endpoint() {
        let txt = r#"
DASHSCOPE_API_KEY=sk-0123456789abcdef0123456789abcdef
BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1
"#;
        let ex = extract(txt);
        assert_eq!(ex.pairs.len(), 1, "pairs: {:?}", ex.pairs);
        assert!(ex.pairs[0].endpoint.contains("dashscope.aliyuncs.com"));
        assert!(endpoint_fits(KeyKind::OpenAi, &ex.pairs[0].endpoint));
    }

    #[test]
    fn skips_placeholders_and_docs() {
        let txt = r#"
OPENAI_API_KEY=sk-proj-YOUR_API_KEY_HERE_1234567890
api_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
https://github.com/foo/bar/blob/main/README.md
BASE_URL=https://api.telegram.org/bot
"#;
        let ex = extract(txt);
        assert!(ex.pairs.is_empty(), "unexpected pairs: {:?}", ex.pairs);
    }

    #[test]
    fn normalizes_suffix_paths() {
        assert_eq!(
            normalize("https://relay.foo.net/v1/chat/completions").unwrap(),
            "https://relay.foo.net/v1"
        );
        assert_eq!(normalize("api.foo.ru/v1").unwrap(), "https://api.foo.ru/v1");
        assert_eq!(normalize("https://foo.ai/about").unwrap(), "https://foo.ai");
    }

    #[test]
    fn pairs_multiple_keys_to_nearest() {
        let txt = r#"
EP1=https://api.one.dev/v1
K1=sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8
EP2=https://api.two.dev/v1
K2=sk-Z9Y8X7W6V5U4T3S2R1Q0P9O8N7M6L5K4J3H2G1F
"#;
        let ex = extract(txt);
        assert_eq!(ex.pairs.len(), 2);
        assert_eq!(ex.pairs[0].endpoint, "https://api.one.dev/v1");
        assert_eq!(ex.pairs[1].endpoint, "https://api.two.dev/v1");
    }

    #[test]
    fn allows_api_hosts_but_not_marketing() {
        assert_eq!(
            normalize("https://api.openai.com/v1").unwrap(),
            "https://api.openai.com/v1"
        );
        assert!(normalize("https://platform.openai.com/docs").is_none());
        assert!(normalize("https://openai.com").is_none());
        assert_eq!(
            normalize("https://api.anthropic.com/v1").unwrap(),
            "https://api.anthropic.com/v1"
        );
    }

    #[test]
    fn tts_keys_are_classified_from_context() {
        let eleven = format!("ELEVENLABS_API_KEY=sk_{}", "a1b2c3d4e5f6g7h8i9j0".repeat(3));
        let ex = extract(&eleven);
        assert!(ex.keys.iter().any(|k| k.kind == KeyKind::ElevenLabs));
        assert!(endpoint_fits(
            KeyKind::ElevenLabs,
            "https://api.elevenlabs.io/v1"
        ));
        let fish = format!("FISH_API_KEY={}", "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6");
        let ex = extract(&fish);
        assert!(ex.keys.iter().any(|k| k.kind == KeyKind::FishAudio));
        assert!(endpoint_fits(
            KeyKind::FishAudio,
            "https://api.fish.audio/v1"
        ));
    }

    #[test]
    fn provider_endpoint_fit() {
        assert!(endpoint_fits(KeyKind::OpenAi, "https://api.relay.dev/v1"));
        assert!(endpoint_fits(
            KeyKind::OpenAi,
            "https://dashscope.aliyuncs.com/compatible-mode/v1"
        ));
        assert!(endpoint_fits(
            KeyKind::OpenAi,
            "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"
        ));
        assert!(!endpoint_fits(KeyKind::OpenAi, "https://app.tavily.com"));
        assert!(!endpoint_fits(
            KeyKind::OpenAi,
            "https://ridein-zimbabwe.netlify.app"
        ));
        assert!(!endpoint_fits(
            KeyKind::HuggingFace,
            "https://api.tavily.com/v1"
        ));
        assert!(endpoint_fits(
            KeyKind::HuggingFace,
            "https://router.huggingface.co/v1"
        ));
        assert!(!endpoint_fits(KeyKind::Generic, "https://api.tavily.com"));
        assert!(is_official_endpoint("https://api.deepseek.com"));
        assert!(is_official_endpoint("https://openrouter.ai/api/v1"));
        assert!(is_priority_official_endpoint(
            "https://openrouter.ai/api/v1"
        ));
        assert!(is_official_endpoint("https://api.moonshot.cn/v1"));
        assert!(endpoint_fits(KeyKind::Generic, "https://api.deepseek.com"));
        assert!(endpoint_fits(
            KeyKind::Generic,
            "https://api.moonshot.cn/v1"
        ));
        assert!(endpoint_fits(
            KeyKind::Generic,
            "https://api.aicredits.in/v1"
        ));
        // OpenRouter's official host is not a generic relay.
        assert!(!endpoint_fits(
            KeyKind::Generic,
            "https://openrouter.ai/api/v1"
        ));
        assert!(!endpoint_fits(
            KeyKind::OpenAi,
            "https://openrouter.ai/api/v1"
        ));
        assert!(endpoint_fits(
            KeyKind::OpenRouter,
            "https://openrouter.ai/api/v1"
        ));
        assert!(!endpoint_fits(
            KeyKind::OpenRouter,
            "https://api.relay.dev/v1"
        ));
        assert!(endpoint_fits_ex(
            KeyKind::OpenAi,
            "https://aicredits.in",
            true
        ));
        assert!(!endpoint_fits_ex(
            KeyKind::OpenAi,
            "https://aicredits.in",
            false
        ));
    }

    #[test]
    fn groq_keys_are_not_generic_candidates() {
        let txt = "GROQ_API_KEY=gsk_0123456789abcdefghijklmnopqrstuvwxyz
https://api.example.com/v1";
        let ex = extract(txt);
        assert!(
            ex.keys.iter().all(|k| !k.key.starts_with("gsk_")),
            "keys: {:?}",
            ex.keys
        );
        assert!(ex.pairs.is_empty(), "pairs: {:?}", ex.pairs);
    }

    #[test]
    fn stripe_keys_are_not_openai() {
        let txt = format!("STRIPE_SECRET=sk_live_{}", "test1234567890abcdef");
        let ex = extract(txt);
        assert!(ex.keys.is_empty(), "keys: {:?}", ex.keys);
    }

    #[test]
    fn decodes_base64_encoded_github_pat() {
        let token = "ghp_1BFBWRUG0DmVAa4KJrv92BSzTcaFEVf4Vd96";
        let encoded = base64::engine::general_purpose::STANDARD.encode(token);
        let txt = format!("github-token: {encoded}");
        let ex = extract(&txt);
        assert!(
            ex.keys
                .iter()
                .any(|k| k.key == token && k.kind == KeyKind::GithubPat),
            "keys: {:?}",
            ex.keys
        );
    }

    #[test]
    fn decodes_urlsafe_base64_github_pat() {
        let token = "ghp_bQAgbFlXYQx0aqp64zOPh8qyr0BauUij2gwL";
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token);
        let txt = format!("secret: {encoded}");
        let ex = extract(&txt);
        assert!(
            ex.keys
                .iter()
                .any(|k| k.key == token && k.kind == KeyKind::GithubPat),
            "keys: {:?}",
            ex.keys
        );
    }

    #[test]
        fn detects_dashscope_classic_and_env_family() {
            // sk- + 32 hex must be DashScope, not a generic OpenAI-shaped key.
            let ex = extract("DASHSCOPE_API_KEY=sk-0123456789abcdef0123456789abcdef");
            assert_eq!(ex.keys.len(), 1);
            assert_eq!(ex.keys[0].kind, KeyKind::DashScope);

            // MODELSCOPE_TOKEN / TONGYI_QIANWEN_API_KEY were invisible to the old
            // env regex — they must be extracted now.
            let ex2 = extract("MODELSCOPE_TOKEN=sk-11223344556677889900aabbccddeeff");
            assert!(!ex2.keys.is_empty(), "modelscope token not extracted");

            // ZhipuAI id.secret shape.
            let ex3 = extract("ZHIPU_API_KEY=0123456789abcdef0123456789abcdef.SECRET12345");
            assert!(!ex3.keys.is_empty(), "zai key not extracted");
        }
    }
