//! Search planning: provider registry and query expansion.
//!
//! The scanner used to know only a handful of hard-coded provider pivots.
//! This module keeps the provider catalog in one place and turns a target
//! into a much wider, provider-aware set of GitHub/repository queries.

#[derive(Clone, Copy)]
pub struct Provider {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub hosts: &'static [&'static str],
    pub env_vars: &'static [&'static str],
    pub prefixes: &'static [&'static str],
    pub contexts: &'static [&'static str],
}

/// Providers that are deliberately searched for a generic `api_key` target.
/// A named target only gets its own provider dorks, so a `modelscope` scan
/// cannot suddenly search for OpenRouter keys.
pub const PRIORITY: &[&str] = &[
    "openai",
    "openrouter",
    "deepseek",
    "dashscope",
    "anthropic",
    "moonshot",
    "xai",
    "modelscope",
    "seedance",
    "fish_audio",
    "elevenlabs",
];

pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "openai",
        aliases: &["openai", "gpt-4", "gpt-5", "chatgpt", "open ai"],
        hosts: &["api.openai.com"],
        env_vars: &["OPENAI_API_KEY", "OPENAI_KEY", "AZURE_OPENAI_API_KEY"],
        prefixes: &["sk-proj-", "sk-live-"],
        contexts: &["openai", "chatgpt"],
    },
    Provider {
        name: "anthropic",
        aliases: &["anthropic", "claude"],
        hosts: &["api.anthropic.com"],
        env_vars: &["ANTHROPIC_API_KEY", "CLAUDE_API_KEY"],
        prefixes: &["sk-ant-"],
        contexts: &["anthropic", "claude"],
    },
    Provider {
        name: "openrouter",
        aliases: &["openrouter", "open router"],
        hosts: &["openrouter.ai"],
        env_vars: &["OPENROUTER_API_KEY", "OPENROUTER_KEY"],
        prefixes: &["sk-or-v1-"],
        contexts: &["openrouter"],
    },
    Provider {
        name: "deepseek",
        aliases: &["deepseek", "deep seek"],
        hosts: &["api.deepseek.com", "api.deepseek.cn"],
        env_vars: &["DEEPSEEK_API_KEY", "DEEPSEEK_KEY"],
        prefixes: &["sk-"],
        contexts: &["deepseek"],
    },
    Provider {
        name: "dashscope",
        aliases: &[
            "dashscope",
            "bailian",
            "qwen",
            "tongyi",
            "aliyun",
            "百炼",
            "通义",
            "阿里云",
        ],
        hosts: &[
            "dashscope.aliyuncs.com",
            "dashscope-intl.aliyuncs.com",
            "maas.aliyuncs.com",
        ],
        env_vars: &[
            "DASHSCOPE_API_KEY",
            "ALIBABA_CLOUD_API_KEY",
            "BAILIAN_API_KEY",
            "QWEN_API_KEY",
            "DASHSCOPE_TOKEN",
            "DASHSCOPE_KEY",
            "DASHSCOPE_LLM_API_KEY",
            "DASH_SCOPE_API_KEY",
            "ALIYUN_DASHSCOPE_API_KEY",
            "BAILIAN_TOKEN",
            "BAILIAN_KEY",
            "QWEN_TOKEN",
            "QWEN_KEY",
            "QWEN_LLM_API_KEY",
            "QWEN_DASHSCOPE_API_KEY",
            "TONGYI_API_KEY",
            "TONGYI_TOKEN",
            "TONGYI_QIANWEN_API_KEY",
            "TONGYI_QIANWEN_TOKEN",
        ],
        prefixes: &["sk-ws-", "sk-sp-", "sk-"],
        contexts: &["dashscope", "百炼", "通义", "qwen"],
    },
    Provider {
        name: "moonshot",
        aliases: &["moonshot", "kimi", "月之暗面"],
        hosts: &["api.moonshot.ai", "api.moonshot.cn"],
        env_vars: &["MOONSHOT_API_KEY", "KIMI_API_KEY"],
        prefixes: &["sk-"],
        contexts: &["moonshot", "kimi"],
    },
    Provider {
        name: "radeon",
        aliases: &["radeon", "amd cloud", "token factory"],
        hosts: &["developer.amd.com.cn"],
        env_vars: &["RADEON_API_KEY", "AMD_API_KEY", "AMD_CLOUD_KEY"],
        prefixes: &["rc-"],
        contexts: &["radeon", "amd"],
    },
    Provider {
        name: "xai",
        aliases: &["xai", "x.ai", "grok"],
        hosts: &["api.x.ai"],
        env_vars: &["XAI_API_KEY", "GROK_API_KEY"],
        prefixes: &["xai-"],
        contexts: &["xai", "grok"],
    },
    Provider {
        name: "modelscope",
        aliases: &["modelscope", "model scope", "魔搭"],
        hosts: &["api-inference.modelscope.cn", "modelscope.cn"],
        env_vars: &["MODELSCOPE_API_KEY", "MODELSCOPE_TOKEN"],
        prefixes: &["ms-"],
        contexts: &["modelscope", "魔搭"],
    },
    Provider {
        name: "seedance",
        aliases: &[
            "seedance",
            "doubao",
            "volcengine",
            "volcengine ark",
            "ark api",
        ],
        hosts: &["ark.cn-beijing.volces.com", "volces.com"],
        env_vars: &["SEEDANCE_API_KEY", "ARK_API_KEY", "VOLCENGINE_API_KEY"],
        prefixes: &[],
        contexts: &["seedance", "doubao", "volcengine"],
    },
    Provider {
        name: "fish_audio",
        aliases: &["fishaudio", "fish audio", "fish.audio"],
        hosts: &["api.fish.audio"],
        env_vars: &["FISH_API_KEY", "FISH_AUDIO_API_KEY", "FISH_AUDIO_TOKEN"],
        prefixes: &[],
        contexts: &["fishaudio", "fish audio"],
    },
    Provider {
        name: "elevenlabs",
        aliases: &["elevenlabs", "eleven labs", "elevenlabs.io"],
        hosts: &["api.elevenlabs.io"],
        env_vars: &["ELEVENLABS_API_KEY", "ELEVEN_LABS_API_KEY", "XI_API_KEY"],
        prefixes: &["sk_"],
        contexts: &["elevenlabs", "eleven labs"],
    },
    Provider {
        name: "google",
        aliases: &["gemini", "google ai", "googleai", "google ai studio"],
        hosts: &["generativelanguage.googleapis.com"],
        env_vars: &["GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_GENAI_API_KEY"],
        prefixes: &["AIza"],
        contexts: &["gemini", "google ai"],
    },
    Provider {
        name: "together",
        aliases: &["together", "together.ai", "together ai"],
        hosts: &["api.together.xyz"],
        env_vars: &["TOGETHER_API_KEY"],
        prefixes: &[],
        contexts: &["together ai"],
    },
    Provider {
        name: "fireworks",
        aliases: &["fireworks", "fireworks.ai"],
        hosts: &["api.fireworks.ai"],
        env_vars: &["FIREWORKS_API_KEY"],
        prefixes: &[],
        contexts: &["fireworks ai"],
    },
    Provider {
        name: "perplexity",
        aliases: &["perplexity", "pplx"],
        hosts: &["api.perplexity.ai"],
        env_vars: &["PERPLEXITY_API_KEY", "PPLX_API_KEY"],
        prefixes: &["pplx-"],
        contexts: &["perplexity"],
    },
    Provider {
        name: "cohere",
        aliases: &["cohere"],
        hosts: &["api.cohere.ai", "api.cohere.com"],
        env_vars: &["COHERE_API_KEY"],
        prefixes: &[],
        contexts: &["cohere"],
    },
    Provider {
        name: "nvidia",
        aliases: &["nvidia", "nvidia nim"],
        hosts: &["integrate.api.nvidia.com"],
        env_vars: &["NVIDIA_API_KEY", "NIM_API_KEY"],
        prefixes: &["nvapi-"],
        contexts: &["nvidia nim"],
    },
    Provider {
        name: "huggingface",
        aliases: &["huggingface", "hugging face", "hf"],
        hosts: &["router.huggingface.co", "huggingface.co"],
        env_vars: &["HF_TOKEN", "HUGGINGFACE_API_KEY", "HUGGING_FACE_TOKEN"],
        prefixes: &["hf_"],
        contexts: &["huggingface", "hugging face"],
    },
    Provider {
        name: "replicate",
        aliases: &["replicate"],
        hosts: &["api.replicate.com"],
        env_vars: &["REPLICATE_API_TOKEN", "REPLICATE_API_KEY"],
        prefixes: &["r8_"],
        contexts: &["replicate"],
    },
    Provider {
        name: "cloudflare",
        aliases: &["cloudflare", "workers ai"],
        hosts: &["api.cloudflare.com"],
        env_vars: &["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_API_KEY"],
        prefixes: &[],
        contexts: &["cloudflare workers ai"],
    },
    Provider {
        name: "novita",
        aliases: &["novita", "novita.ai"],
        hosts: &["api.novita.ai"],
        env_vars: &["NOVITA_API_KEY"],
        prefixes: &["sk_"],
        contexts: &["novita"],
    },
    Provider {
        name: "deepinfra",
        aliases: &["deepinfra", "deep infra"],
        hosts: &["api.deepinfra.com"],
        env_vars: &["DEEPINFRA_API_KEY"],
        prefixes: &[],
        contexts: &["deepinfra"],
    },
    Provider {
        name: "hyperbolic",
        aliases: &["hyperbolic"],
        hosts: &["api.hyperbolic.xyz"],
        env_vars: &["HYPERBOLIC_API_KEY"],
        prefixes: &[],
        contexts: &["hyperbolic"],
    },
    Provider {
        name: "lambda",
        aliases: &["lambda labs", "lambdalabs", "lambda.ai"],
        hosts: &["api.lambdalabs.com"],
        env_vars: &["LAMBDA_API_KEY"],
        prefixes: &[],
        contexts: &["lambda labs"],
    },
    Provider {
        name: "nebius",
        aliases: &["nebius"],
        hosts: &["api.studio.nebius.ai"],
        env_vars: &["NEBIUS_API_KEY"],
        prefixes: &[],
        contexts: &["nebius"],
    },
    Provider {
        name: "chutes",
        aliases: &["chutes", "chutes.ai"],
        hosts: &["llm.chutes.ai"],
        env_vars: &["CHUTES_API_KEY"],
        prefixes: &[],
        contexts: &["chutes"],
    },
    Provider {
        name: "targon",
        aliases: &["targon"],
        hosts: &["api.targon.com"],
        env_vars: &["TARGON_API_KEY"],
        prefixes: &[],
        contexts: &["targon"],
    },
    Provider {
        name: "ai21",
        aliases: &["ai21", "ai21 labs"],
        hosts: &["api.ai21.com"],
        env_vars: &["AI21_API_KEY"],
        prefixes: &[],
        contexts: &["ai21"],
    },
    Provider {
        name: "voyage",
        aliases: &["voyage", "voyageai"],
        hosts: &["api.voyageai.com"],
        env_vars: &["VOYAGE_API_KEY"],
        prefixes: &[],
        contexts: &["voyageai"],
    },
    Provider {
        name: "jina",
        aliases: &["jina", "jina.ai"],
        hosts: &["api.jina.ai"],
        env_vars: &["JINA_API_KEY"],
        prefixes: &[],
        contexts: &["jina"],
    },
    Provider {
        name: "upstage",
        aliases: &["upstage"],
        hosts: &["api.upstage.ai"],
        env_vars: &["UPSTAGE_API_KEY"],
        prefixes: &[],
        contexts: &["upstage"],
    },
    Provider {
        name: "siliconflow",
        aliases: &["siliconflow", "silicon flow", "硅基流动"],
        hosts: &["api.siliconflow.cn"],
        env_vars: &["SILICONFLOW_API_KEY", "SILICON_FLOW_API_KEY"],
        prefixes: &["sk-"],
        contexts: &["siliconflow", "硅基流动"],
    },
    Provider {
        name: "baichuan",
        aliases: &["baichuan", "百川"],
        hosts: &["api.baichuan-ai.com"],
        env_vars: &["BAICHUAN_API_KEY"],
        prefixes: &[],
        contexts: &["baichuan", "百川"],
    },
    Provider {
        name: "stepfun",
        aliases: &["stepfun", "step fun", "阶跃星辰"],
        hosts: &["api.stepfun.com"],
        env_vars: &["STEPFUN_API_KEY"],
        prefixes: &[],
        contexts: &["stepfun", "阶跃星辰"],
    },
    Provider {
        name: "zhipu",
        aliases: &["zhipu", "智谱", "bigmodel"],
        hosts: &["open.bigmodel.cn"],
        env_vars: &["ZHIPUAI_API_KEY", "ZHIPU_API_KEY"],
        prefixes: &[],
        contexts: &["zhipu", "智谱"],
    },
    Provider {
        name: "minimax",
        aliases: &["minimax", "mini max"],
        hosts: &["api.minimax.chat", "api.minimaxi.com"],
        env_vars: &["MINIMAX_API_KEY"],
        prefixes: &[],
        contexts: &["minimax"],
    },
    Provider {
        name: "hunyuan",
        aliases: &["hunyuan", "混元"],
        hosts: &["hunyuan.tencentcloudapi.com"],
        env_vars: &["HUNYUAN_API_KEY", "TENCENTCLOUD_SECRET_KEY"],
        prefixes: &[],
        contexts: &["hunyuan", "混元"],
    },
    Provider {
        name: "exa",
        aliases: &["exa", "exa.ai", "exa labs"],
        hosts: &["api.exa.ai"],
        env_vars: &["EXA_API_KEY", "EXA_KEY"],
        prefixes: &[],
        contexts: &["exa.ai"],
    },
    Provider {
        name: "firecrawl",
        aliases: &["firecrawl", "fire crawl"],
        hosts: &["api.firecrawl.dev"],
        env_vars: &["FIRECRAWL_API_KEY", "FIRECRAWL_KEY"],
        prefixes: &["fc-"],
        contexts: &["firecrawl"],
    },
    Provider {
        name: "tavily",
        aliases: &["tavily"],
        hosts: &["api.tavily.com"],
        env_vars: &["TAVILY_API_KEY", "TAVILY_KEY"],
        prefixes: &["tvly-"],
        contexts: &["tavily"],
    },
    Provider {
        name: "serper",
        aliases: &["serper"],
        hosts: &["google.serper.dev"],
        env_vars: &["SERPER_API_KEY", "SERPER_KEY"],
        prefixes: &[],
        contexts: &["serper"],
    },
    Provider {
        name: "serpapi",
        aliases: &["serpapi", "serp api"],
        hosts: &["serpapi.com"],
        env_vars: &["SERPAPI_API_KEY", "SERP_API_KEY", "SERPAPI_KEY"],
        prefixes: &[],
        contexts: &["serpapi"],
    },
    Provider {
        name: "apify",
        aliases: &["apify"],
        hosts: &["api.apify.com"],
        env_vars: &["APIFY_API_TOKEN", "APIFY_TOKEN", "APIFY_API_KEY"],
        prefixes: &["apify_api_"],
        contexts: &["apify"],
    },
    Provider {
        name: "hunter",
        aliases: &["hunter", "hunter.io"],
        hosts: &["api.hunter.io"],
        env_vars: &["HUNTER_API_KEY", "HUNTERIO_API_KEY", "HUNTER_KEY"],
        prefixes: &[],
        contexts: &["hunter.io"],
    },
    Provider {
        name: "brave",
        aliases: &["brave search", "brave api"],
        hosts: &["api.search.brave.com"],
        env_vars: &["BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY"],
        prefixes: &[],
        contexts: &["brave.com"],
    },
    Provider {
        name: "diffbot",
        aliases: &["diffbot"],
        hosts: &["api.diffbot.com"],
        env_vars: &["DIFFBOT_TOKEN", "DIFFBOT_API_TOKEN", "DIFFBOT_API_KEY"],
        prefixes: &[],
        contexts: &["diffbot"],
    },
    Provider {
        name: "moz",
        aliases: &["moz", "moz links api"],
        hosts: &["lsapi.seomoz.org"],
        env_vars: &["MOZ_ACCESS_ID", "MOZ_SECRET_KEY", "MOZ_API_KEY"],
        prefixes: &[],
        contexts: &["seomoz"],
    },
    Provider {
        name: "semrush",
        aliases: &["semrush"],
        hosts: &["api.semrush.com"],
        env_vars: &["SEMRUSH_API_KEY", "SEMRUSH_TOKEN"],
        prefixes: &[],
        contexts: &["semrush"],
    },
    Provider {
        name: "serpstat",
        aliases: &["serpstat"],
        hosts: &["api.serpstat.com"],
        env_vars: &["SERPSTAT_API_KEY", "SERPSTAT_TOKEN"],
        prefixes: &[],
        contexts: &["serpstat"],
    },
    Provider {
        name: "dataforseo",
        aliases: &["dataforseo", "data for seo"],
        hosts: &["api.dataforseo.com"],
        env_vars: &["DATAFORSEO_LOGIN", "DATAFORSEO_PASSWORD", "DATAFORSEO_API_KEY"],
        prefixes: &[],
        contexts: &["dataforseo"],
    },
    Provider {
        name: "apollo",
        aliases: &["apollo.io", "apollo api"],
        hosts: &["api.apollo.io"],
        env_vars: &["APOLLO_API_KEY", "APOLLOIO_API_KEY"],
        prefixes: &[],
        contexts: &["apollo.io"],
    },
    Provider {
        name: "lusha",
        aliases: &["lusha"],
        hosts: &["api.lusha.com"],
        env_vars: &["LUSHA_API_KEY", "LUSHA_KEY"],
        prefixes: &[],
        contexts: &["lusha"],
    },
    Provider {
        name: "peopledatalabs",
        aliases: &["people data labs", "pdl"],
        hosts: &["api.peopledatalabs.com"],
        env_vars: &["PDL_API_KEY", "PEOPLE_DATA_LABS_API_KEY"],
        prefixes: &[],
        contexts: &["peopledatalabs"],
    },
    Provider {
        name: "zerobounce",
        aliases: &["zerobounce"],
        hosts: &["api.zerobounce.net"],
        env_vars: &["ZEROBOUNCE_API_KEY"],
        prefixes: &[],
        contexts: &["zerobounce"],
    },
    Provider {
        name: "crunchbase",
        aliases: &["crunchbase"],
        hosts: &["api.crunchbase.com"],
        env_vars: &["CRUNCHBASE_API_KEY", "CB_USER_KEY"],
        prefixes: &[],
        contexts: &["crunchbase"],
    },
    Provider {
        name: "spider",
        aliases: &["spider.cloud", "spider api"],
        hosts: &["api.spider.cloud"],
        env_vars: &["SPIDER_API_KEY", "SPIDER_API_TOKEN"],
        prefixes: &["sp-"],
        contexts: &["spider.cloud"],
    },
    Provider {
        name: "linkup",
        aliases: &["linkup"],
        hosts: &["api.linkup.co"],
        env_vars: &["LINKUP_API_KEY"],
        prefixes: &[],
        contexts: &["linkup"],
    },
    Provider {
        name: "search1api",
        aliases: &["search1api", "search1 api"],
        hosts: &["api.search1api.io"],
        env_vars: &["SEARCH1API_API_KEY"],
        prefixes: &[],
        contexts: &["search1api"],
    },
    Provider {
        name: "brightdata",
        aliases: &["bright data", "brightdata", "super proxy"],
        hosts: &["brd.superproxy.io"],
        env_vars: &["BRIGHT_DATA_API_TOKEN", "BRIGHTDATA_API_TOKEN", "SBR_ACCESS_TOKEN"],
        prefixes: &[],
        contexts: &["brightdata"],
    },
    Provider {
        name: "polygon",
        aliases: &["polygon.io", "polygon api"],
        hosts: &["api.polygon.io"],
        env_vars: &["POLYGON_API_KEY"],
        prefixes: &[],
        contexts: &["polygon.io"],
    },
    Provider {
        name: "twelvedata",
        aliases: &["twelvedata", "twelve data"],
        hosts: &["api.twelvedata.com"],
        env_vars: &["TWELVE_DATA_API_KEY", "TWELVEDATA_API_KEY"],
        prefixes: &[],
        contexts: &["twelvedata"],
    },
    Provider {
        name: "finnhub",
        aliases: &["finnhub"],
        hosts: &["finnhub.io"],
        env_vars: &["FINNHUB_API_KEY"],
        prefixes: &[],
        contexts: &["finnhub"],
    },
    Provider {
        name: "marketstack",
        aliases: &["marketstack"],
        hosts: &["api.marketstack.com"],
        env_vars: &["MARKETSTACK_API_KEY"],
        prefixes: &[],
        contexts: &["marketstack"],
    },
    Provider {
        name: "coingecko",
        aliases: &["coingecko"],
        hosts: &["api.coingecko.com"],
        env_vars: &["COINGECKO_API_KEY", "CG_PRO_API_KEY"],
        prefixes: &["cg-"],
        contexts: &["coingecko"],
    },
    Provider {
        name: "eodhd",
        aliases: &["eodhd", "eod historical data"],
        hosts: &["eodhd.com"],
        env_vars: &["EODHD_API_TOKEN", "EODHD_API_KEY", "EOD_ACCESS_TOKEN"],
        prefixes: &[],
        contexts: &["eodhd"],
    },
    Provider {
        name: "tikhub",
        aliases: &["tikhub"],
        hosts: &["api.tikhub.io"],
        env_vars: &["TIKHUB_API_KEY"],
        prefixes: &[],
        contexts: &["tikhub"],
    },
    Provider {
        name: "scrapecreators",
        aliases: &["scrapecreators"],
        hosts: &["api.scrapecreators.com"],
        env_vars: &["SCRAPECREATORS_API_KEY"],
        prefixes: &[],
        contexts: &["scrapecreators"],
    },
    Provider {
        name: "olostep",
        aliases: &["olostep"],
        hosts: &["api.olostep.com"],
        env_vars: &["OLOSTEP_API_KEY"],
        prefixes: &[],
        contexts: &["olostep"],
    },
    Provider {
        name: "piapi",
        aliases: &["piapi"],
        hosts: &["api.piapi.ai"],
        env_vars: &["PIAPI_API_KEY"],
        prefixes: &[],
        contexts: &["piapi"],
    },
    Provider {
        name: "minimax",
        aliases: &["minimax", "minimaxi"],
        hosts: &["api.minimaxi.com", "api.minimax.io"],
        env_vars: &["MINIMAX_API_KEY", "MINIMAX_GROUP_ID", "MINIMAX_TOKEN"],
        prefixes: &[],
        contexts: &["minimax"],
    },
];

/// True for a query built from the provider registry. The autonomous
/// scheduler uses this to give new provider env/host dorks the same head start
/// as the original hand-written OpenAI/DeepSeek pack.
pub fn is_provider_dork(q: &str) -> bool {
    let low = q.to_ascii_lowercase();
    PROVIDERS.iter().any(|p| {
        p.env_vars
            .iter()
            .chain(p.hosts.iter())
            .any(|needle| low.contains(&needle.to_ascii_lowercase()))
    })
}

fn is_generic(target: &str) -> bool {
    matches!(
        target
            .trim_matches('"')
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "api_key"
            | "apikey"
            | "api key"
            | "sk-"
            | "sk"
            | "token"
            | "secret"
            | "key"
            | "api token"
            | "api secret"
    )
}

fn matches(provider: &Provider, low: &str) -> bool {
    provider
        .aliases
        .iter()
        .chain(provider.hosts.iter())
        .chain(provider.env_vars.iter())
        .any(|needle| low.contains(&needle.to_ascii_lowercase()))
}

fn dedupe(mut queries: Vec<String>, limit: usize) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    queries.retain(|q| {
        let q = q.trim();
        !q.is_empty() && seen.insert(q.to_string())
    });
    queries.truncate(limit);
    queries
}

/// Provider-aware dorks. A named target only gets its own provider family;
/// a truly generic target fans out to the priority providers.
pub fn provider_dorks(target: &str) -> Vec<String> {
    let low = target.to_ascii_lowercase();
    let generic = is_generic(target);
    let mut selected: Vec<&Provider> = PROVIDERS.iter().filter(|p| matches(p, &low)).collect();
    if selected.is_empty() && generic {
        selected = PROVIDERS
            .iter()
            .filter(|p| PRIORITY.contains(&p.name))
            .collect();
    }
    if selected.is_empty() {
        return Vec::new();
    }
    let selected_limit = if generic { PRIORITY.len() } else { 10 };
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(90))
        .format("%Y-%m-%d")
        .to_string();
    let mut out = Vec::new();
    for p in selected.into_iter().take(selected_limit) {
        // Put the exact assignment shapes and the host pivot first. A
        // search limited to 8 dorks must still contain env, filename and the
        // provider host, not just three variants of the same env name.
        let first_var = p.env_vars.first().copied().unwrap_or_default();
        if !first_var.is_empty() {
            out.push(format!("\"{first_var}\" extension:env"));
            out.push(format!("\"{first_var}\" filename:.env"));
            out.push(format!("\"{first_var}\" in:file"));
            if generic && p.name == "openai" {
                out.push(format!("\"{first_var}\" pushed:>{cutoff} in:file"));
            }
        }
        if !generic {
            if let Some(host) = p.hosts.first() {
                out.push(format!("\"{host}\" \"sk-\" in:file"));
            }
        }
        if !generic {
            for var in p.env_vars.iter().take(2) {
                for suffix in [
                    "path:.env",
                    "path:.github/workflows",
                    "path:config",
                    "extension:yaml",
                    "extension:json",
                    "filename:docker-compose.yml",
                ] {
                    out.push(format!("\"{var}\" {suffix}"));
                }
            }
        }
        if p.name == "seedance" {
            // Ark keys are UUID-like; the model host+name is the strongest
            // signal and must survive a short manual dork budget.
            out.push("\"doubao-seedance\" \"SEEDANCE_API_KEY\" in:file".into());
            out.push("\"doubao-seedance\" \"ARK_API_KEY\" in:file".into());
        }
        if generic {
            if let Some(host) = p.hosts.first() {
                out.push(format!("\"{host}\" \"sk-\" in:file"));
            }
            continue;
        }
        for var in p.env_vars.iter().skip(1).take(2) {
            out.push(format!("\"{var}\" extension:env"));
            out.push(format!("\"{var}\" filename:.env"));
            out.push(format!("\"{var}\" in:file"));
        }
        for host in p.hosts.iter().take(3) {
            out.push(format!("\"{host}\" \"sk-\" in:file"));
            out.push(format!("\"{host}\" \"api_key\" in:file"));
            out.push(format!("\"{host}\" \"base_url\" in:file"));
            out.push(format!("\"{host}\" \"sk-\" path:.env"));
            out.push(format!("\"{host}\" \"sk-\" path:.github/workflows"));
            out.push(format!("\"{host}\" \"api_key\" extension:yaml"));
            out.push(format!("\"{host}\" \"api_key\" extension:json"));
        }
        for prefix in p.prefixes.iter().take(2) {
            if *prefix != "sk-" {
                out.push(format!("\"{prefix}\" extension:env"));
            }
        }
        for ctx in p.contexts.iter().take(2) {
            out.push(format!("\"{ctx}\" \"api key\" in:file"));
            out.push(format!("\"{ctx}\" \"base_url\" in:file"));
        }
        if !first_var.is_empty() {
            out.push(format!("\"{first_var}\" pushed:>{cutoff} in:file"));
        }
    }
    // Common secret-bearing filenames that are not covered by extension:env.
    for suffix in [
        "filename:.env.local",
        "filename:.env.production",
        "filename:.env.development",
        "filename:.env.staging",
        "filename:secrets.yaml",
        "filename:secrets.yml",
        "filename:credentials",
        "filename:application.properties",
        "filename:appsettings.json",
    ] {
        out.push(format!("{target} {suffix}"));
    }
    dedupe(out, if generic { 70 } else { 120 })
}

/// Queries for the autonomous pair lane. This is intentionally wider than
/// the old seven-provider seed, but still uses one env var and one host per
/// provider so the scheduler can cover every provider without one family
/// monopolising the 10/min search budget.
pub fn auto_queries() -> Vec<String> {
    let mut out = Vec::new();
    for p in PROVIDERS.iter().filter(|p| PRIORITY.contains(&p.name)) {
        for var in p.env_vars.iter().take(1) {
            out.push(format!("\"{var}\" in:file"));
            out.push(format!("\"{var}\" extension:env"));
        }
        for host in p.hosts.iter().take(1) {
            // Moonshot China is force-invalid by product policy.
            if *host == "api.moonshot.cn" {
                continue;
            }
            out.push(format!("\"{host}\" \"sk-\" in:file"));
        }
    }
    dedupe(out, 200)
}

/// Repository pivots used by autonomous discovery. Kept separate from manual
/// dorks because repository search accepts `topic:` and `pushed:` qualifiers.
pub fn repo_queries(cutoff: &str) -> Vec<String> {
    let mut out = Vec::new();
    for topic in [
        "openai",
        "llm",
        "ai-agents",
        "chatgpt",
        "gpt",
        "llm-api",
        "rag",
        "new-api",
        "one-api",
        "litellm",
        "openai-proxy",
        "api-relay",
        "chatgpt-api",
        "deepseek",
        "dashscope",
        "qwen",
        "ai-api",
        "llm-gateway",
        "api-gateway",
        "reverse-proxy",
        "anthropic",
        "claude",
        "openrouter",
        "moonshot",
        "kimi",
        "modelscope",
        "siliconflow",
        "fish-audio",
        "elevenlabs",
        "seedance",
        "volcengine",
        "ai-tools",
        "secrets",
        "github-actions",
    ] {
        out.push(format!("topic:{topic} pushed:>{cutoff}"));
    }
    for p in PROVIDERS.iter().filter(|p| PRIORITY.contains(&p.name)) {
        for var in p.env_vars.iter().take(2) {
            out.push(format!("\"{var}\" pushed:>{cutoff}"));
        }
        for host in p.hosts.iter().take(1) {
            out.push(format!("\"{host}\" pushed:>{cutoff}"));
        }
    }
    dedupe(out, 200)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_target_does_not_leak_other_providers() {
        let qs = provider_dorks("modelscope");
        assert!(qs.iter().any(|q| q.contains("MODELSCOPE_API_KEY")));
        assert!(qs.iter().all(|q| !q.contains("OPENROUTER_API_KEY")));
    }

    #[test]
    fn generic_target_expands_to_priority_pack() {
        let qs = provider_dorks("api_key");
        assert!(qs.iter().any(|q| q.contains("OPENAI_API_KEY")));
        assert!(qs.iter().any(|q| q.contains("DASHSCOPE_API_KEY")));
        assert!(qs.len() >= 10);
    }

    #[test]
    fn repo_queries_are_wide_and_deduplicated() {
        let qs = repo_queries("2026-01-01");
        assert!(qs.iter().any(|q| q.contains("topic:openai")));
        assert!(qs.iter().any(|q| q.contains("DEEPSEEK_API_KEY")));
        let unique: std::collections::HashSet<_> = qs.iter().collect();
        assert_eq!(unique.len(), qs.len());
    }
}
