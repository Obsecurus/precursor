const scenarios = [
  {
    id: "packet",
    label: "Packet Triage",
    subtitle: "mixed service payloads",
    title: "Pre-Protocol Packet Triage",
    description:
      "Cluster mixed HTTP/TLS/SSH/DNS/Modbus payloads before parser commitment. Useful when traffic is noisy or service identity is ambiguous.",
    command: `cat samples/scenarios/pre-protocol-packet-triage/payloads.b64 \\
  | precursor -p samples/scenarios/pre-protocol-packet-triage/patterns.pcre \\
      -m base64 -t -d --similarity-mode lzjd -P --protocol-hints --stats`,
    stdoutFile: "data/packet_triage.ndjson",
    stderrFile: "data/packet_triage.stderr",
    links: [
      { label: "scenario assets", href: "https://github.com/Obsecurus/precursor/tree/main/samples/scenarios/pre-protocol-packet-triage" },
      { label: "captured stdout", href: "data/packet_triage.ndjson" },
      { label: "captured stats", href: "data/packet_triage.stderr" },
    ],
    chips: ["input: base64", "similarity: lzjd", "single-packet: on"],
  },
  {
    id: "firmware",
    label: "Firmware",
    subtitle: "binary fragment tags",
    title: "Firmware Fragment Sorting",
    description:
      "Tag ELF/PE/uImage/gzip-style fragments from arbitrary blob streams and prioritize artifacts worth deeper reversing.",
    command: `cat samples/scenarios/firmware-fragment-triage/payloads.hex \\
  | precursor -p samples/scenarios/firmware-fragment-triage/patterns.pcre \\
      -m hex -t -d --similarity-mode lzjd -P --protocol-hints --stats`,
    stdoutFile: "data/firmware_triage.ndjson",
    stderrFile: "data/firmware_triage.stderr",
    links: [
      { label: "scenario assets", href: "https://github.com/Obsecurus/precursor/tree/main/samples/scenarios/firmware-fragment-triage" },
      { label: "captured stdout", href: "data/firmware_triage.ndjson" },
      { label: "captured stats", href: "data/firmware_triage.stderr" },
    ],
    chips: ["input: hex", "blob-safe", "binary workflows"],
  },
  {
    id: "sigma",
    label: "Sigma Pipeline",
    subtitle: "rule intent + similarity",
    title: "Sigma Rule to Precursor Pipeline",
    description:
      "Load Sigma YAML directly, convert keyword selectors to named captures, and keep condition logic while adding similarity context.",
    command: `cat samples/scenarios/sigma-linux-shell-command-triage/payloads.log \\
  | precursor --sigma-rule samples/scenarios/sigma-linux-shell-command-triage/sigma_rule.yml \\
      -m string -t -d --similarity-mode lzjd --protocol-hints --stats`,
    stdoutFile: "data/sigma_triage.ndjson",
    stderrFile: "data/sigma_triage.stderr",
    links: [
      { label: "scenario assets", href: "https://github.com/Obsecurus/precursor/tree/main/samples/scenarios/sigma-linux-shell-command-triage" },
      { label: "captured stdout", href: "data/sigma_triage.ndjson" },
      { label: "captured stats", href: "data/sigma_triage.stderr" },
    ],
    chips: ["sigma condition", "input: string", "detection tuning"],
  },
  {
    id: "log4shell",
    label: "PCAP-Derived",
    subtitle: "public log4shell corpus",
    title: "Public Log4Shell Probe Clustering",
    description:
      "Replay request payloads extracted from a public Log4Shell PCAP corpus to identify exploit-stage families and outliers quickly.",
    command: `cat samples/scenarios/public-log4shell-foxit-pcap/payloads.string \\
  | precursor -p samples/scenarios/public-log4shell-foxit-pcap/patterns.pcre \\
      -m string -t -d --similarity-mode fbhash -P --protocol-hints --stats`,
    stdoutFile: "data/log4shell_triage.ndjson",
    stderrFile: "data/log4shell_triage.stderr",
    links: [
      { label: "scenario assets", href: "https://github.com/Obsecurus/precursor/tree/main/samples/scenarios/public-log4shell-foxit-pcap" },
      { label: "captured stdout", href: "data/log4shell_triage.ndjson" },
      { label: "captured stats", href: "data/log4shell_triage.stderr" },
    ],
    chips: ["input: string", "similarity: fbhash", "protocol hints"],
  },
];

const loopSteps = [
  {
    id: "step1",
    label: "Step 1",
    title: "Baseline: generic HTTP method tag",
    summary: "Start broad to measure corpus shape before adding specific exploit semantics.",
    stderrFile: "data/loop_step1.stderr",
  },
  {
    id: "step2",
    label: "Step 2",
    title: "Targeted tag pack",
    summary: "Add exploit-class, JNDI, LDAP, and Java user-agent captures to separate families.",
    stderrFile: "data/loop_step2.stderr",
  },
  {
    id: "step3",
    label: "Step 3",
    title: "Switch similarity backend",
    summary: "Use FBHash mode to compare family cohesion and candidate ranking shifts.",
    stderrFile: "data/loop_step3.stderr",
  },
  {
    id: "step4",
    label: "Step 4",
    title: "Codex-guided refinement",
    summary: "Validate an additional encoded-JNDI pattern proposed from loop stats and output examples.",
    stderrFile: "data/loop_step4_codex.stderr",
  },
];

const heroTeasers = [
  `{"tags":["http_method"],"similarity_hash":"lzjd:128:...","protocol_label":"http","protocol_confidence":0.93}`,
  `{"tags":["sigma_*"],"sigma_rule_matches":["Suspicious Shell Commands"],"similarity_hash":"lzjd:128:..."}`,
  `{"tags":["gzip_magic"],"similarity_hash":"lzjd:92:...","protocol_label":"compressed_binary"}`,
  `{"tags":["urlencoded_jndi","ldap_scheme"],"similarity_hash":"fbhash:227:...","protocol_label":"http"}`,
];

const scenarioTabs = [
  { id: "command", label: "Command" },
  { id: "stdout", label: "Output" },
  { id: "stats", label: "Stats" },
  { id: "insights", label: "Insights" },
];

const state = {
  scenarioId: scenarios[0].id,
  scenarioTab: "command",
  loopStepId: loopSteps[0].id,
  teaserIdx: 0,
  scenarioCache: new Map(),
  loopCache: new Map(),
};

const el = {
  heroMetrics: document.getElementById("hero-metrics"),
  teaserCode: document.getElementById("teaser-code"),
  teaserButton: document.getElementById("cycle-teaser"),

  scenarioList: document.getElementById("scenario-list"),
  scenarioName: document.getElementById("scenario-name"),
  scenarioDescription: document.getElementById("scenario-description"),
  scenarioMeta: document.getElementById("scenario-meta"),
  scenarioTabs: document.getElementById("scenario-tabs"),
  scenarioPanelLabel: document.getElementById("scenario-panel-label"),
  scenarioPanel: document.getElementById("scenario-panel"),
  scenarioLinks: document.getElementById("scenario-links"),
  copyCommand: document.getElementById("copy-command"),

  loopSteps: document.getElementById("loop-steps"),
  loopStepTitle: document.getElementById("loop-step-title"),
  loopStepSummary: document.getElementById("loop-step-summary"),
  loopBars: document.getElementById("loop-bars"),
  loopJson: document.getElementById("loop-json"),

  llmWhy: document.getElementById("llm-why"),
  llmRefinements: document.getElementById("llm-refinements"),
  llmPattern: document.getElementById("llm-pattern"),
  llmCommand: document.getElementById("llm-command"),
  llmRisk: document.getElementById("llm-risk"),
  llmDeltas: document.getElementById("llm-deltas"),
  llmRuntime: document.getElementById("llm-runtime"),

  installCommand: document.getElementById("install-command"),
  copyInstall: document.getElementById("copy-install"),
};

function extractJsonObjects(text) {
  const objects = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escape = false;

  for (let i = 0; i < text.length; i += 1) {
    const ch = text[i];

    if (inString) {
      if (escape) {
        escape = false;
      } else if (ch === "\\") {
        escape = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      continue;
    }

    if (ch === "{") {
      if (depth === 0) {
        start = i;
      }
      depth += 1;
      continue;
    }

    if (ch === "}") {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        const candidate = text.slice(start, i + 1);
        try {
          objects.push(JSON.parse(candidate));
        } catch (_err) {
          // ignore malformed blocks
        }
        start = -1;
      }
    }
  }

  return objects;
}

async function fetchText(path) {
  const response = await fetch(path);
  if (!response.ok) {
    throw new Error(`failed to fetch ${path}`);
  }
  return response.text();
}

function renderHeroMetrics() {
  const metrics = [
    { title: "4", note: "public scenario classes live on this page" },
    { title: "4", note: "similarity modes (TLSH, LZJD, FBHash, MRSHv2 adapter)" },
    { title: "JSON", note: "stable tags + similarity + protocol fields" },
  ];

  if (!el.heroMetrics) {
    return;
  }

  el.heroMetrics.innerHTML = "";
  metrics.forEach((metric) => {
    const card = document.createElement("article");
    card.className = "metric";

    const value = document.createElement("strong");
    value.textContent = metric.title;

    const note = document.createElement("small");
    note.textContent = metric.note;

    card.appendChild(value);
    card.appendChild(note);
    el.heroMetrics.appendChild(card);
  });
}

function renderTeaser() {
  if (!el.teaserCode) {
    return;
  }
  el.teaserCode.textContent = heroTeasers[state.teaserIdx];
}

function cycleTeaser() {
  state.teaserIdx = (state.teaserIdx + 1) % heroTeasers.length;
  renderTeaser();
}

function renderScenarioList() {
  if (!el.scenarioList) {
    return;
  }

  el.scenarioList.innerHTML = "";
  scenarios.forEach((scenario) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "scenario-button";
    button.dataset.id = scenario.id;
    button.setAttribute("aria-selected", scenario.id === state.scenarioId ? "true" : "false");

    const title = document.createElement("strong");
    title.textContent = scenario.label;

    const subtitle = document.createElement("small");
    subtitle.textContent = scenario.subtitle;

    button.appendChild(title);
    button.appendChild(subtitle);
    button.addEventListener("click", () => {
      state.scenarioId = scenario.id;
      state.scenarioTab = "command";
      renderScenarioList();
      renderScenario();
    });

    el.scenarioList.appendChild(button);
  });
}

function renderScenarioTabs() {
  if (!el.scenarioTabs) {
    return;
  }

  el.scenarioTabs.innerHTML = "";
  scenarioTabs.forEach((tab) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "tab";
    button.dataset.id = tab.id;
    button.textContent = tab.label;
    button.setAttribute("aria-selected", tab.id === state.scenarioTab ? "true" : "false");
    button.addEventListener("click", () => {
      state.scenarioTab = tab.id;
      renderScenario();
    });
    el.scenarioTabs.appendChild(button);
  });
}

function summarizeScenario(stats, hints) {
  if (!stats) {
    return "Stats are not available for this scenario.";
  }

  const matches = (stats.Match && stats.Match.Matches) || [];
  const top = matches
    .slice()
    .sort((a, b) => (b.Matches || 0) - (a.Matches || 0))
    .slice(0, 4)
    .map((entry) => `${entry.Name}:${entry.Matches}`)
    .join(", ");

  const parts = [
    `Input count: ${stats.Input?.Count ?? "n/a"}`,
    `Pattern lines: ${stats.Match?.Patterns ?? "n/a"}`,
    `Total matches: ${stats.Match?.TotalMatches ?? "n/a"}`,
    `Similarity mode: ${stats.Environment?.SimilarityMode ?? "n/a"}`,
    `Top tags: ${top || "none"}`,
  ];

  if (hints && Array.isArray(hints.Candidates)) {
    parts.push(`Protocol hint candidates: ${hints.Candidates.length}`);
  }

  return parts.join("\n");
}

async function loadScenarioRuntime(scenario) {
  if (state.scenarioCache.has(scenario.id)) {
    return state.scenarioCache.get(scenario.id);
  }

  const runtime = {
    stdout: "",
    stderr: "",
    stats: null,
    hints: null,
    error: null,
  };

  try {
    const [stdout, stderr] = await Promise.all([
      fetchText(scenario.stdoutFile),
      fetchText(scenario.stderrFile),
    ]);

    runtime.stdout = stdout.trim();
    runtime.stderr = stderr.trim();

    const objects = extractJsonObjects(runtime.stderr);
    runtime.stats = objects.find((obj) => Object.prototype.hasOwnProperty.call(obj, "---PRECURSOR_STATISTICS---")) || null;
    runtime.hints = objects.find((obj) => Object.prototype.hasOwnProperty.call(obj, "---PRECURSOR_PROTOCOL_HINTS---")) || null;
  } catch (error) {
    runtime.error = error.message;
  }

  state.scenarioCache.set(scenario.id, runtime);
  return runtime;
}

async function renderScenario() {
  const scenario = scenarios.find((entry) => entry.id === state.scenarioId) || scenarios[0];
  if (!scenario) {
    return;
  }

  if (el.scenarioName) {
    el.scenarioName.textContent = scenario.title;
  }
  if (el.scenarioDescription) {
    el.scenarioDescription.textContent = scenario.description;
  }

  if (el.scenarioMeta) {
    el.scenarioMeta.innerHTML = "";
    scenario.chips.forEach((chip) => {
      const span = document.createElement("span");
      span.className = "chip";
      span.textContent = chip;
      el.scenarioMeta.appendChild(span);
    });
  }

  if (el.scenarioLinks) {
    el.scenarioLinks.innerHTML = scenario.links
      .map((link) => `<a href="${link.href}" target="_blank" rel="noreferrer">${link.label}</a>`)
      .join(" | ");
  }

  renderScenarioTabs();
  const runtime = await loadScenarioRuntime(scenario);

  let label = "Command";
  let content = scenario.command;

  if (runtime.error) {
    label = "Error";
    content = runtime.error;
  } else if (state.scenarioTab === "stdout") {
    label = "Captured stdout (.ndjson)";
    content = runtime.stdout || "No output captured.";
  } else if (state.scenarioTab === "stats") {
    label = "Captured --stats stderr";
    content = runtime.stats ? JSON.stringify(runtime.stats, null, 2) : runtime.stderr || "No stats available.";
  } else if (state.scenarioTab === "insights") {
    label = "Analyst summary";
    content = summarizeScenario(runtime.stats, runtime.hints);
  }

  if (el.scenarioPanelLabel) {
    el.scenarioPanelLabel.textContent = label;
  }
  if (el.scenarioPanel) {
    el.scenarioPanel.textContent = content;
  }
}

function renderLoopSteps() {
  if (!el.loopSteps) {
    return;
  }

  el.loopSteps.innerHTML = "";
  loopSteps.forEach((step) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "loop-step";
    button.dataset.id = step.id;
    button.setAttribute("aria-selected", step.id === state.loopStepId ? "true" : "false");

    const title = document.createElement("strong");
    title.textContent = `${step.label} - ${step.title}`;

    const subtitle = document.createElement("small");
    subtitle.textContent = step.summary;

    button.appendChild(title);
    button.appendChild(subtitle);

    button.addEventListener("click", () => {
      state.loopStepId = step.id;
      renderLoopSteps();
      renderLoopDetail();
    });

    el.loopSteps.appendChild(button);
  });
}

async function loadLoopStep(step) {
  if (state.loopCache.has(step.id)) {
    return state.loopCache.get(step.id);
  }

  const data = {
    stats: null,
    hints: null,
    error: null,
  };

  try {
    const raw = await fetchText(step.stderrFile);
    const blocks = extractJsonObjects(raw);
    data.stats = blocks.find((obj) => Object.prototype.hasOwnProperty.call(obj, "---PRECURSOR_STATISTICS---")) || null;
    data.hints = blocks.find((obj) => Object.prototype.hasOwnProperty.call(obj, "---PRECURSOR_PROTOCOL_HINTS---")) || null;
  } catch (error) {
    data.error = error.message;
  }

  state.loopCache.set(step.id, data);
  return data;
}

function addBarMetric(container, label, value, maxValue) {
  const row = document.createElement("div");
  row.className = "bar-row";

  const head = document.createElement("div");
  head.className = "bar-head";
  const name = document.createElement("span");
  const score = document.createElement("strong");
  name.textContent = label;
  score.textContent = String(value);
  head.appendChild(name);
  head.appendChild(score);

  const track = document.createElement("div");
  track.className = "bar-track";

  const fill = document.createElement("div");
  fill.className = "bar-fill";
  const width = maxValue > 0 ? Math.round((value / maxValue) * 100) : 0;
  fill.style.width = `${Math.min(100, width)}%`;

  track.appendChild(fill);
  row.appendChild(head);
  row.appendChild(track);
  container.appendChild(row);
}

async function renderLoopDetail() {
  const selected = loopSteps.find((step) => step.id === state.loopStepId) || loopSteps[0];
  if (!selected) {
    return;
  }

  const allData = await Promise.all(loopSteps.map((step) => loadLoopStep(step)));
  const currentData = allData[loopSteps.findIndex((step) => step.id === selected.id)] || {};

  if (el.loopStepTitle) {
    el.loopStepTitle.textContent = `${selected.label}: ${selected.title}`;
  }
  if (el.loopStepSummary) {
    el.loopStepSummary.textContent = selected.summary;
  }

  if (el.loopBars) {
    el.loopBars.innerHTML = "";

    if (currentData.error || !currentData.stats) {
      const line = document.createElement("p");
      line.textContent = currentData.error || "No stats available.";
      el.loopBars.appendChild(line);
    } else {
      const metrics = {
        patterns: currentData.stats.Match?.Patterns || 0,
        matches: currentData.stats.Match?.TotalMatches || 0,
        hashes: currentData.stats.Match?.HashesGenerated || 0,
        candidates: Array.isArray(currentData.hints?.Candidates) ? currentData.hints.Candidates.length : 0,
      };

      const max = {
        patterns: Math.max(...allData.map((entry) => entry.stats?.Match?.Patterns || 0), 1),
        matches: Math.max(...allData.map((entry) => entry.stats?.Match?.TotalMatches || 0), 1),
        hashes: Math.max(...allData.map((entry) => entry.stats?.Match?.HashesGenerated || 0), 1),
        candidates: Math.max(...allData.map((entry) => (entry.hints?.Candidates || []).length || 0), 1),
      };

      addBarMetric(el.loopBars, "Pattern count", metrics.patterns, max.patterns);
      addBarMetric(el.loopBars, "Total matches", metrics.matches, max.matches);
      addBarMetric(el.loopBars, "Hashes generated", metrics.hashes, max.hashes);
      addBarMetric(el.loopBars, "Hint candidates", metrics.candidates, max.candidates);
    }
  }

  if (el.loopJson) {
    if (currentData.stats) {
      const excerpt = {
        Match: {
          Patterns: currentData.stats.Match?.Patterns || 0,
          TotalMatches: currentData.stats.Match?.TotalMatches || 0,
          Matches: currentData.stats.Match?.Matches || [],
        },
        Compare: currentData.stats.Compare || {},
        Environment: currentData.stats.Environment || {},
      };
      el.loopJson.textContent = JSON.stringify(excerpt, null, 2);
    } else {
      el.loopJson.textContent = currentData.error || "No JSON available.";
    }
  }
}

function findMatchCount(stats, name) {
  const matches = stats?.Match?.Matches || [];
  const item = matches.find((entry) => entry.Name === name);
  return item ? item.Matches : 0;
}

function renderLlmDeltaRow(label, value) {
  const card = document.createElement("div");
  card.className = "delta";

  const title = document.createElement("strong");
  title.textContent = label;

  const desc = document.createElement("span");
  desc.textContent = value;

  card.appendChild(title);
  card.appendChild(desc);
  return card;
}

async function renderLlmSection() {
  let codex = null;
  let claudeStatus = null;

  try {
    codex = JSON.parse(await fetchText("data/llm_codex_demo.json"));
  } catch (_err) {
    codex = null;
  }

  try {
    claudeStatus = JSON.parse(await fetchText("data/llm_claude_status.json"));
  } catch (_err) {
    claudeStatus = null;
  }

  if (codex) {
    if (el.llmWhy) {
      el.llmWhy.textContent = codex.why_it_matters;
    }
    if (el.llmRefinements) {
      el.llmRefinements.innerHTML = "";
      (codex.refinements || []).forEach((line) => {
        const li = document.createElement("li");
        li.textContent = line;
        el.llmRefinements.appendChild(li);
      });
    }
    if (el.llmPattern) {
      el.llmPattern.textContent = codex.new_pattern || "";
    }
    if (el.llmCommand) {
      el.llmCommand.textContent = codex.next_command || "";
    }
    if (el.llmRisk) {
      el.llmRisk.textContent = codex.risk || "";
    }
  }

  const [step3, step4] = await Promise.all([
    loadLoopStep(loopSteps.find((entry) => entry.id === "step3") || loopSteps[2]),
    loadLoopStep(loopSteps.find((entry) => entry.id === "step4") || loopSteps[3]),
  ]);

  if (el.llmDeltas) {
    el.llmDeltas.innerHTML = "";

    if (step3?.stats && step4?.stats) {
      const patternsBefore = step3.stats.Match?.Patterns || 0;
      const patternsAfter = step4.stats.Match?.Patterns || 0;
      const matchesBefore = step3.stats.Match?.TotalMatches || 0;
      const matchesAfter = step4.stats.Match?.TotalMatches || 0;
      const newTagHits = findMatchCount(step4.stats, "jndi_remote_lookup");
      const hintBefore = (step3.hints?.Candidates || []).length;
      const hintAfter = (step4.hints?.Candidates || []).length;

      el.llmDeltas.appendChild(
        renderLlmDeltaRow("Pattern lines", `${patternsBefore} -> ${patternsAfter}`),
      );
      el.llmDeltas.appendChild(
        renderLlmDeltaRow("Total matches", `${matchesBefore} -> ${matchesAfter}`),
      );
      el.llmDeltas.appendChild(
        renderLlmDeltaRow("New tag hits", `jndi_remote_lookup: ${newTagHits}`),
      );
      el.llmDeltas.appendChild(
        renderLlmDeltaRow("Hint candidates", `${hintBefore} -> ${hintAfter}`),
      );
    } else {
      el.llmDeltas.appendChild(renderLlmDeltaRow("Status", "Loop comparison data unavailable"));
    }
  }

  if (el.llmRuntime) {
    const lines = [];
    lines.push("Codex CLI run: completed locally and saved to site/data/llm_codex_demo.json");
    lines.push("Validation run: cargo run against step-4 corpus output (loop_step4_codex.*)");
    if (claudeStatus) {
      lines.push(`Claude CLI auth state: loggedIn=${claudeStatus.loggedIn}`);
      if (!claudeStatus.loggedIn) {
        lines.push("Claude demo execution is pending local CLI authentication.");
      }
    }
    lines.push("Note: shell-level precursor binary on this machine is older than current repo features; validation used cargo run from this branch.");
    el.llmRuntime.textContent = lines.join("\n");
  }
}

async function copyText(text, button) {
  if (!button) {
    return;
  }
  try {
    await navigator.clipboard.writeText(text || "");
    const original = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => {
      button.textContent = original || "Copy";
    }, 900);
  } catch (_err) {
    const original = button.textContent;
    button.textContent = "Manual copy";
    setTimeout(() => {
      button.textContent = original || "Copy";
    }, 1200);
  }
}

function wireCopyButtons() {
  if (el.copyCommand) {
    el.copyCommand.addEventListener("click", async () => {
      const current = scenarios.find((entry) => entry.id === state.scenarioId) || scenarios[0];
      await copyText(current?.command || "", el.copyCommand);
    });
  }

  if (el.copyInstall && el.installCommand) {
    el.copyInstall.addEventListener("click", async () => {
      await copyText(el.installCommand.textContent || "", el.copyInstall);
    });
  }
}

async function init() {
  renderHeroMetrics();
  renderTeaser();

  if (el.teaserButton) {
    el.teaserButton.addEventListener("click", () => {
      cycleTeaser();
    });
  }

  setInterval(() => {
    cycleTeaser();
  }, 4500);

  renderScenarioList();
  await renderScenario();

  renderLoopSteps();
  await renderLoopDetail();

  await renderLlmSection();
  wireCopyButtons();
}

init();
