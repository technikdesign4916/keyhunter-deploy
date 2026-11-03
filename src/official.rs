//! First-party provider signatures used to keep the official search lane
//! precise. A query is official only when it names one of these hosts, env
//! variable, or a provider-unique key prefix. Generic `sk-` alone is not
//! promoted: that would flood the lane with relay noise.

pub struct Provider {
    pub name: &'static str,
    pub hosts: &'static [&'static str],
    pub env: &'static [&'static str],
    pub prefixes: &'static [&'static str],
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "openai",
        hosts: &["api.openai.com"],
        env: &["OPENAI_API_KEY", "OPENAI_KEY"],
        prefixes: &["sk-proj-", "sk-svcacct-", "sk-admin-"],
    },
    Provider {
        name: "deepseek",
        hosts: &["api.deepseek.com"],
        env: &["DEEPSEEK_API_KEY", "DEEPSEEK_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "openrouter",
        hosts: &["openrouter.ai"],
        env: &["OPENROUTER_API_KEY", "OPENROUTER_KEY"],
        prefixes: &["sk-or-v1-"],
    },
    Provider {
        name: "moonshot",
        // The China endpoint is force-invalid by operator policy and must not
        // consume official search slots. The international endpoint remains
        // eligible.
        hosts: &["api.moonshot.ai"],
        env: &["MOONSHOT_API_KEY", "MOONSHOT_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "anthropic",
        hosts: &["api.anthropic.com"],
        env: &["ANTHROPIC_API_KEY", "ANTHROPIC_KEY"],
        prefixes: &["sk-ant-"],
    },
    Provider {
        name: "xai",
        hosts: &["api.x.ai"],
        env: &["XAI_API_KEY", "XAI_KEY"],
        prefixes: &["xai-"],
    },
    Provider {
        name: "dashscope",
        hosts: &[
            "dashscope.aliyuncs.com",
            "dashscope-intl.aliyuncs.com",
            "dashscope-us.aliyuncs.com",
        ],
        env: &["DASHSCOPE_API_KEY", "BAILIAN_API_KEY", "QWEN_API_KEY", "DASHSCOPE_TOKEN", "DASHSCOPE_KEY", "DASHSCOPE_LLM_API_KEY", "DASH_SCOPE_API_KEY", "ALIYUN_DASHSCOPE_API_KEY", "ALIBABA_CLOUD_API_KEY", "BAILIAN_TOKEN", "BAILIAN_KEY", "QWEN_TOKEN", "QWEN_KEY", "QWEN_LLM_API_KEY", "QWEN_DASHSCOPE_API_KEY", "TONGYI_API_KEY", "TONGYI_TOKEN", "TONGYI_QIANWEN_API_KEY", "TONGYI_QIANWEN_TOKEN"],
        // Classic quality keys are seeded explicitly below. `sk-ws-` is a
        // workspace credential and is deliberately not a quality target.
        prefixes: &[],
    },
    Provider {
        name: "exa",
        hosts: &[
            "api.exa.ai",
        ],
        env: &["EXA_API_KEY", "EXA_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "firecrawl",
        hosts: &[
            "api.firecrawl.dev",
        ],
        env: &["FIRECRAWL_API_KEY", "FIRECRAWL_KEY"],
        prefixes: &["fc-"],
    },
    Provider {
        name: "tavily",
        hosts: &[
            "api.tavily.com",
        ],
        env: &["TAVILY_API_KEY", "TAVILY_KEY"],
        prefixes: &["tvly-"],
    },
    Provider {
        name: "serper",
        hosts: &[
            "google.serper.dev",
        ],
        env: &["SERPER_API_KEY", "SERPER_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "serpapi",
        hosts: &[
            "serpapi.com",
        ],
        env: &["SERPAPI_API_KEY", "SERP_API_KEY", "SERPAPI_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "apify",
        hosts: &[
            "api.apify.com",
        ],
        env: &["APIFY_API_TOKEN", "APIFY_TOKEN"],
        prefixes: &["apify_api_"],
    },
    Provider {
        name: "hunter",
        hosts: &[
            "api.hunter.io",
        ],
        env: &["HUNTER_API_KEY", "HUNTERIO_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "brave",
        hosts: &[
            "api.search.brave.com",
        ],
        env: &["BRAVE_API_KEY", "BRAVE_SEARCH_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "diffbot",
        hosts: &[
            "api.diffbot.com",
        ],
        env: &["DIFFBOT_TOKEN", "DIFFBOT_API_TOKEN"],
        prefixes: &[],
    },
    Provider {
        name: "moz",
        hosts: &[
            "lsapi.seomoz.org",
            "api.moz.com",
        ],
        env: &["MOZ_ACCESS_ID", "MOZ_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "semrush",
        hosts: &[
            "api.semrush.com",
        ],
        env: &["SEMRUSH_API_KEY", "SEMRUSH_TOKEN"],
        prefixes: &[],
    },
    Provider {
        name: "serpstat",
        hosts: &[
            "api.serpstat.com",
        ],
        env: &["SERPSTAT_API_KEY", "SERPSTAT_TOKEN"],
        prefixes: &[],
    },
    Provider {
        name: "dataforseo",
        hosts: &[
            "api.dataforseo.com",
        ],
        env: &["DATAFORSEO_LOGIN", "DATAFORSEO_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "apollo",
        hosts: &[
            "api.apollo.io",
        ],
        env: &["APOLLO_API_KEY", "APOLLOIO_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "lusha",
        hosts: &[
            "api.lusha.com",
        ],
        env: &["LUSHA_API_KEY", "LUSHA_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "peopledatalabs",
        hosts: &[
            "api.peopledatalabs.com",
        ],
        env: &["PDL_API_KEY", "PEOPLE_DATA_LABS_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "zerobounce",
        hosts: &[
            "api.zerobounce.net",
        ],
        env: &["ZEROBOUNCE_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "crunchbase",
        hosts: &[
            "api.crunchbase.com",
        ],
        env: &["CRUNCHBASE_API_KEY", "CB_USER_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "spider",
        hosts: &[
            "api.spider.cloud",
        ],
        env: &["SPIDER_API_KEY", "SPIDER_API_TOKEN"],
        prefixes: &[],
    },
    Provider {
        name: "linkup",
        hosts: &[
            "api.linkup.co",
        ],
        env: &["LINKUP_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "search1api",
        hosts: &[
            "api.search1api.io",
        ],
        env: &["SEARCH1API_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "brightdata",
        hosts: &[
            "brd.superproxy.io",
        ],
        env: &["BRIGHT_DATA_API_TOKEN", "SBR_ACCESS_TOKEN"],
        prefixes: &[],
    },
    Provider {
        name: "polygon",
        hosts: &[
            "api.polygon.io",
        ],
        env: &["POLYGON_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "twelvedata",
        hosts: &[
            "api.twelvedata.com",
        ],
        env: &["TWELVE_DATA_API_KEY", "TWELVEDATA_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "finnhub",
        hosts: &[
            "finnhub.io",
        ],
        env: &["FINNHUB_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "marketstack",
        hosts: &[
            "api.marketstack.com",
        ],
        env: &["MARKETSTACK_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "coingecko",
        hosts: &[
            "api.coingecko.com",
        ],
        env: &["COINGECKO_API_KEY", "CG_PRO_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "eodhd",
        hosts: &[
            "eodhd.com",
        ],
        env: &["EODHD_API_TOKEN", "EODHD_API_KEY", "EOD_ACCESS_TOKEN"],
        prefixes: &[],
    },
    Provider {
        name: "tikhub",
        hosts: &[
            "api.tikhub.io",
        ],
        env: &["TIKHUB_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "scrapecreators",
        hosts: &[
            "api.scrapecreators.com",
        ],
        env: &["SCRAPECREATORS_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "olostep",
        hosts: &[
            "api.olostep.com",
        ],
        env: &["OLOSTEP_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "piapi",
        hosts: &[
            "api.piapi.ai",
        ],
        env: &["PIAPI_API_KEY"],
        prefixes: &[],
    },
    Provider {
        name: "minimax",
        hosts: &[
            "api.minimaxi.com",
            "api.minimax.io",
        ],
        env: &["MINIMAX_API_KEY", "MINIMAX_GROUP_ID"],
        prefixes: &[],
    },
];

fn host_token_present(query: &str, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    query
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .any(|token| {
            let token = token.trim_matches('.');
            token == host || token.ends_with(&format!(".{host}"))
        })
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Score an official query. `None` means it belongs to the pair lane.
/// The score is a boost for ordering inside the official lane.
pub fn query_score(q: &str) -> Option<i64> {
    let ql = lower(q);
    // Explicitly retired provider: never let an old mixture query
    // (`api.groq.com` + `OPENAI_API_KEY`) re-enter the official lane.
    if ql.contains("groq") || ql.contains("gsk_") || ql.contains("api.moonshot.cn") {
        return None;
    }
    let mut best: Option<i64> = None;
    for p in PROVIDERS {
        let host_hit = p.hosts.iter().any(|h| host_token_present(&ql, h));
        let env_hit = p.env.iter().any(|e| ql.contains(&lower(e)));
        let prefix_hit = p.prefixes.iter().any(|x| ql.contains(&lower(x)));
        if !host_hit && !env_hit && !prefix_hit {
            continue;
        }
        // A unique key prefix is a strong official signal even without a
        // hostname. Host+prefix is the strongest, then env+host, then host.
        let score = if host_hit && prefix_hit {
            340
        } else if host_hit && env_hit {
            325
        } else if host_hit {
            285
        } else if prefix_hit {
            270
        } else {
            250
        };
        best = Some(best.map_or(score, |b| b.max(score)));
    }
    best
}

pub fn is_official_query(q: &str) -> bool {
    query_score(q).is_some()
}

/// DashScope is deliberately dual-lane: the same dork may run in the
/// official lane and again in the pair lane, where relay/workspace shapes are
/// accepted instead of being filtered down to first-party endpoints.
pub fn is_dashscope_query(q: &str) -> bool {
    let ql = lower(q);
    [
        "dashscope",
        "aliyuncs.com",
        "bailian",
        "sk-ws-",
        "qwen_api_key",
        "百炼",
    ]
    .iter()
    .any(|needle| ql.contains(needle))
}

/// High-precision DashScope dorks for classic `sk-…` keys. The extraction
/// layer still enforces the exact `sk-` + 32 hex shape and DashScope
/// context, so these queries cannot silently turn into generic `sk-` noise.
pub fn dashscope_quality_queries() -> &'static [&'static str] {
    &[
        "\"DASHSCOPE_API_KEY=sk-\" extension:env",
        "\"BAILIAN_API_KEY=sk-\" extension:env",
        "\"QWEN_API_KEY=sk-\" extension:env",
        "\"DASHSCOPE_API_KEY\" \"sk-\" extension:env",
        "\"DASHSCOPE_API_KEY\" \"sk-\" filename:.env",
        "\"dashscope.aliyuncs.com\" \"sk-\" extension:env",
        "\"dashscope-intl.aliyuncs.com\" \"sk-\" extension:env",
        "\"dashscope-us.aliyuncs.com\" \"sk-\" extension:env",
        "\"dashscope.aliyuncs.com\" \"sk-\" filename:.env",
        "\"dashscope-intl.aliyuncs.com\" \"sk-\" filename:.env",
        "\"dashscope.aliyuncs.com/compatible-mode/v1\" \"sk-\" in:file",
        "\"dashscope-intl.aliyuncs.com/compatible-mode/v1\" \"sk-\" in:file",
        "\"coding.dashscope.aliyuncs.com\" \"sk-\" in:file",
        "\"coding-intl.dashscope.aliyuncs.com\" \"sk-\" in:file",
        "\"DASHSCOPE_API_KEY\" \"sk-\" in:file",
        "\"BAILIAN_API_KEY\" \"sk-\" in:file",
        "\"QWEN_API_KEY\" \"sk-\" in:file",
        "\"DASHSCOPE_API_KEY\" \"sk-\" extension:py",
        "\"DASHSCOPE_API_KEY\" \"sk-\" extension:yaml",
        "\"DASHSCOPE_API_KEY\" \"sk-\" extension:json",
        "\"DASHSCOPE_API_KEY\" \"sk-\" filename:.env.example",
        "\"dashscope.aliyuncs.com\" \"Bearer sk-\" in:file",
        "\"QWEN_DASHSCOPE_API_KEY=sk-\" extension:env",
        "\"ALIYUN_DASHSCOPE_API_KEY=sk-\" extension:env",
        "\"DASHSCOPE_LLM_API_KEY=sk-\" extension:env",
        "\"TONGYI_QIANWEN_API_KEY=sk-\" extension:env",
        "\"ALIBABA_CLOUD_API_KEY=sk-\" extension:env",
        "\"DASHSCOPE_TOKEN\" \"sk-\" in:file",
        "\"TONGYI_API_KEY\" \"sk-\" in:file",
        "\"QWEN_TOKEN\" \"sk-\" in:file",
        "\"BAILIAN_TOKEN\" \"sk-\" in:file",
        "\"DASHSCOPE_KEY\" \"sk-\" in:file",
        "\"dashscope\" \"sk-\" filename:docker-compose.yml",
        "\"dashscope\" \"sk-\" extension:toml",
        "\"dashscope.aliyuncs.com\" \"sk-\" extension:yaml",
        "\"dashscope.aliyuncs.com\" \"sk-\" extension:json",
        "\"dashscope.aliyuncs.com\" \"sk-\" extension:py",
        "\"dashscope-intl.aliyuncs.com\" \"sk-\" in:file",
        "\"dashscope.aliyuncs.com\" \"sk-\" in:file",
        "\"compatible-mode/v1\" \"sk-\" in:file",
        "\"import dashscope\" \"sk-\" in:file",
        "\"dashscope.api_key\" \"sk-\" in:file",
        "\"qwen-flash\" \"sk-\" in:file",
        "\"qwen-turbo\" \"sk-\" in:file",
        "\"qwen-plus\" \"sk-\" in:file",
        "\"qwen-max\" \"sk-\" in:file",
        "\"qwen3\" \"sk-\" extension:py",
        "\"通义\" \"sk-\" extension:env",
        "\"百炼\" \"sk-\" in:file",
        "\"sk-ws-\" \"dashscope\" in:file",
        "\"sk-ws-\" \"bailian\" in:file",
        "\"sk-ws-\" \"qwen\" in:file",
        "\"DASHSCOPE_API_KEY\" \"sk-\" extension:ts",
        "\"DASHSCOPE_API_KEY\" \"sk-\" extension:js",
        "\"DASHSCOPE_API_KEY\" \"sk-\" extension:go",
        "\"DASHSCOPE_API_KEY\" \"sk-\" extension:sh",
        "\"DASHSCOPE_API_KEY\" \"sk-\" extension:toml",
        "\"DASHSCOPE_API_KEY\" \"sk-\" filename:.env.production",
        "\"DASHSCOPE_API_KEY\" \"sk-\" filename:.env.local",
        "\"BAILIAN_API_KEY\" \"sk-\" extension:yaml",
        "\"QWEN_API_KEY\" \"sk-\" extension:json",
        "\"QWEN_API_KEY\" \"sk-\" extension:py",
        "\"DASHSCOPE_WORKSPACE_API_KEY\" in:file",
    ]
}

/// Extra query seeds for the official lane. They are inserted once and are
/// lane-classified by `query_score`; duplicates are ignored by SQLite.
pub fn seed_queries() -> Vec<(String, i64)> {
    let mut out = Vec::new();
    for p in PROVIDERS {
        for host in p.hosts {
            for prefix in p.prefixes {
                // Common OpenAI/OpenRouter/Anthropic prefixes produce
                // candidates; administrative prefixes are rarer and must not
                // monopolize the first official slots.
                let base = match *prefix {
                    "sk-proj-" => 390,
                    "sk-or-v1-" => 388,
                    "sk-ant-" => 386,
                    "sk-ws-" => 384,
                    "sk-svcacct-" => 338,
                    "sk-admin-" => 334,
                    _ => 350,
                };
                out.push((format!("\"{host}\" \"{prefix}\" in:file"), base));
                out.push((format!("\"{host}\" \"{prefix}\" filename:.env"), base - 10));
                out.push((format!("\"{prefix}\" filename:.env"), base - 20));
                out.push((format!("\"{prefix}\" extension:env"), base + 5));
            }
            out.push((format!("\"{host}\" filename:.env"), 330));
            for env in p.env {
                out.push((format!("\"{env}\" \"{host}\" in:file"), 340));
                out.push((format!("\"{env}\" \"{host}\" filename:.env"), 372));
                out.push((format!("\"{env}\" extension:env"), 405));
                out.push((format!("\"{env}\" \"{host}\" extension:env"), 398));
                for prefix in p.prefixes {
                    out.push((format!("\"{env}={prefix}\" extension:env"), 408));
                }
                if p.prefixes.is_empty() {
                    out.push((format!("\"{env}=sk-\" extension:env"), 406));
                }
                out.push((format!("\"{env}\" in:file"), 305));
                out.push((format!("\"{env}\" filename:.env"), 362));
            }
        }
    }
    for q in dashscope_quality_queries() {
        out.push(((*q).to_string(), 430));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// Source Atlas queries for Bing/Brave-style adapters.
pub fn source_queries() -> Vec<String> {
    let mut out = Vec::new();
    for p in PROVIDERS {
        for host in p.hosts {
            out.push(format!("\"{host}\" \"api key\""));
            for prefix in p.prefixes {
                out.push(format!("\"{host}\" \"{prefix}\""));
            }
            for env in p.env {
                out.push(format!("\"{env}\" \"{host}\""));
            }
            out.push(format!("\"{host}\" site:pastebin.com"));
        }
    }
    for q in dashscope_quality_queries() {
        out.push((*q).to_string());
    }
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_queries_are_classified_precisely() {
        assert!(is_official_query("\"api.openai.com\" \"sk-proj-\" in:file"));
        assert!(is_official_query(
            "\"openrouter.ai\" \"sk-or-v1-\" extension:env"
        ));
        assert!(is_official_query("\"OPENROUTER_API_KEY\" extension:env"));
        assert!(is_official_query("OPENAI_API_KEY"));
        assert!(is_official_query("\"sk-ant-\" in:file"));
        assert!(is_official_query("\"api.moonshot.ai\""));
        assert!(!is_official_query("sk- in:file"));
        assert!(!is_official_query("api.relay.example sk-"));
        assert!(!is_official_query(
            "\"MOONSHOT_API_KEY\" \"api.moonshot.cn\" in:file"
        ));
        assert!(!is_official_query("openai")); // a bare word is not a lane
        assert!(!is_official_query(
            r#""api.groq.com" "OPENAI_API_KEY" in:file"#
        ));
        assert!(is_dashscope_query(
            r#""DASHSCOPE_API_KEY" "dashscope.aliyuncs.com" extension:env"#
        ));
        assert!(is_dashscope_query(r#""sk-ws-" in:file"#));
        assert!(is_dashscope_query(r#""maas.aliyuncs.com" "sk-""#));
        assert!(!is_dashscope_query(r#""api.openai.com" "sk-proj-""#));
    }

    #[test]
    fn dashscope_quality_pack_targets_classic_sk() {
        let qs = dashscope_quality_queries();
        assert!(qs.iter().any(|q| q.contains("DASHSCOPE_API_KEY=sk-")));
        assert!(qs.iter().any(|q| q.contains("dashscope.aliyuncs.com")));
        assert!(qs.iter().all(|q| q.contains("sk-")));
        assert!(qs.iter().all(|q| !q.contains("sk-ws-")));
        assert!(seed_queries()
            .iter()
            .any(|(q, _)| q == "\"DASHSCOPE_API_KEY=sk-\" extension:env"));
    }

    #[test]
    fn strongest_query_has_high_score() {
        assert!(
            query_score("\"api.openai.com\" \"sk-proj-\" in:file").unwrap()
                > query_score("OPENAI_API_KEY").unwrap()
        );
        assert!(query_score("api.deepseek.com").unwrap() >= 285);
    }
}
