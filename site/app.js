const scenarios = [
  {
    id: "packet-triage",
    label: "Packet Triage",
    title: "Pre-Protocol Packet Triage",
    description:
      "Cluster mixed HTTP/TLS/SSH/DNS/Modbus payloads before parser commitment. Useful for scanner traffic and unknown service discovery.",
    command: `cat samples/scenarios/pre-protocol-packet-triage/payloads.b64 \\
  | precursor -p samples/scenarios/pre-protocol-packet-triage/patterns.pcre \\
      -m base64 -t -d --similarity-mode lzjd -P --protocol-hints`,
    output: `stdout: similarity_hash + protocol_* fields
stderr: ---PRECURSOR_PROTOCOL_HINTS--- with top candidate clusters`,
  },
  {
    id: "firmware-fragments",
    label: "Firmware",
    title: "Firmware Fragment Sorting",
    description:
      "Tag likely ELF/PE/uImage/gzip fragments from arbitrary blob streams and route high-entropy unknowns for deeper reverse engineering.",
    command: `cat samples/scenarios/firmware-fragment-triage/payloads.hex \\
  | precursor -p samples/scenarios/firmware-fragment-triage/patterns.pcre \\
      -m hex -t --similarity-mode lzjd -P`,
    output: `protocol_label typically includes firmware_binary or compressed_binary
tags include file-magic style markers`,
  },
  {
    id: "binary-blob",
    label: "Binary",
    title: "Raw-Binary Blob Mode",
    description:
      "Use the short -B flag to ingest arbitrary raw bytes as one payload record and tag firmware or packet fragments without UTF-8 assumptions.",
    command: `printf '\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00' \\
  | precursor '(?<elf_magic>^\\x7fELF)' -B -t --similarity-mode lzjd -P`,
    output: `expected tag: elf_magic
protocol_label usually resolves to firmware_binary for ELF-like headers`,
  },
  {
    id: "ics-single-packet",
    label: "ICS/OT",
    title: "ICS Modbus Single-Packet Discovery",
    description:
      "Detect Modbus request/response function families from single packets where full DPI context is unavailable.",
    command: `cat samples/scenarios/ics-modbus-single-packet/payloads.hex \\
  | precursor -p samples/scenarios/ics-modbus-single-packet/patterns.pcre \\
      -m hex -t -d --similarity-mode lzjd -P --protocol-hints`,
    output: `cluster boosts improve confidence when payload families repeat
hint candidates can be fed into LLM-assisted rule authoring loops`,
  },
  {
    id: "log4shell-pcap-derived",
    label: "Log4Shell",
    title: "PCAP-Derived Log4Shell Probe Clustering",
    description:
      "Cluster evasive JNDI/LDAP probe strings derived from a public Log4Shell PCAP corpus. This is a pre-parser workflow for exploit spray discovery and rule drafting.",
    command: `cat samples/scenarios/public-log4shell-pcap-derived/payloads.string \\
  | precursor -p samples/scenarios/public-log4shell-pcap-derived/patterns.pcre \\
      -m string -t -d --similarity-mode lzjd -P --protocol-hints`,
    output: `expected tags include jndi_expression + obfuscation_primitive
protocol_label typically resolves to http for these request-shaped probes`,
  },
  {
    id: "foxit-pcap-live",
    label: "PCAP Replay",
    title: "Real PCAP Replay with FBHash",
    description:
      "Replay HTTP requests extracted from a public fox-it Log4Shell PCAP and cluster exploit staging traffic using fbhash mode.",
    command: `cat samples/scenarios/public-log4shell-foxit-pcap/payloads.string \\
  | precursor -p samples/scenarios/public-log4shell-foxit-pcap/patterns.pcre \\
      -m string -t -d --similarity-mode fbhash -P --protocol-hints`,
    output: `tags include urlencoded_jndi, exploit_class_path, and java_user_agent
similarity_hash values are fbhash:* and group replay families cleanly`,
  },
  {
    id: "sigma-shell-triage",
    label: "Sigma",
    title: "Sigma Rule to Precursor Pipeline",
    description:
      "Load Sigma YAML directly, auto-convert keyword selectors to named captures, and score suspicious shell command streams without hand-rewriting regex files.",
    command: `cat samples/scenarios/sigma-linux-shell-command-triage/payloads.log \\
  | precursor --sigma-rule samples/scenarios/sigma-linux-shell-command-triage/sigma_rule.yml \\
      -m string -t -d --similarity-mode lzjd --protocol-hints`,
    output: `tags include sigma_* captures for matched commands
output includes sigma_rule_matches and sigma_rule_ids when condition passes`,
  },
  {
    id: "binwalk-firmware",
    label: "Firmware Blobs",
    title: "Public Firmware Blob Folder Triage",
    description:
      "Run binary folder mode over real binwalk test artifacts and tag romfs/squashfs/cramfs/gzip magic headers in one pass.",
    command: `precursor -p samples/scenarios/public-firmware-binwalk-magic/patterns.pcre \\
  -f samples/scenarios/public-firmware-binwalk-magic/blobs \\
  --input-mode binary -t -d --similarity-mode lzjd -P --protocol-hints`,
    output: `expected tags: gzip_magic, romfs_magic, squashfs_magic, cramfs_magic
useful for firmware triage before full unpacking`,
  },
  {
    id: "zeek-dns-log",
    label: "Zeek DNS",
    title: "Public Zeek DNS Log Triage",
    description:
      "Extract DNS query fields from Zeek JSON logs and cluster suspicious domain families for rapid hunt pivots.",
    command: `cat samples/scenarios/public-zeek-dns-log-triage/payloads.jsonl \\
  | precursor -p samples/scenarios/public-zeek-dns-log-triage/patterns.pcre \\
      -m string -j '.query' -t -d --similarity-mode lzjd --protocol-hints`,
    output: `matches include possible_c2_domain and suspicious_tld tags
query extraction runs through the same JSON contract used in production pipelines`,
  },
];

const demoReels = [
  {
    id: "reel-pcap",
    label: "PCAP Replay",
    title: "Replay: fox-it Log4Shell PCAP -> FBHash clusters",
    intervalMs: 1700,
    frames: [
      `$ samples/scenarios/public-log4shell-foxit-pcap/extract_payloads.sh | head -2
GET /test?q=%24%7B...%7D HTTP/1.1 Host: extracted.local User-Agent: python-requests/2.25.1
GET /ExploitYEKeLeuvob.class HTTP/1.1 Host: extracted.local User-Agent: Java/1.8.0_181`,
      `$ cat samples/scenarios/public-log4shell-foxit-pcap/payloads.string | precursor -p samples/scenarios/public-log4shell-foxit-pcap/patterns.pcre -m string -t -d --similarity-mode fbhash -P
{"tags":["http_method","urlencoded_jndi","ldap_scheme"],"similarity_hash":"fbhash:227:...","protocol_label":"http"}`,
      `{"tags":["http_method","exploit_class_path","java_user_agent"],"similarity_hash":"fbhash:80:...","protocol_label":"http"}
...
Signal: one stage-0 exploit line + repeated class fetch family clusters`,
    ],
  },
  {
    id: "reel-firmware",
    label: "Firmware",
    title: "Replay: binary folder mode on real firmware blobs",
    intervalMs: 1700,
    frames: [
      `$ precursor -p samples/scenarios/public-firmware-binwalk-magic/patterns.pcre -f samples/scenarios/public-firmware-binwalk-magic/blobs --input-mode binary -t -d --similarity-mode lzjd -P
{"tags":["squashfs_magic"],"similarity_hash":"lzjd:128:...","protocol_label":"unknown"}`,
      `{"tags":["romfs_magic"],"similarity_hash":"lzjd:128:...","protocol_label":"unknown"}
{"tags":["cramfs_magic"],"similarity_hash":"lzjd:128:...","protocol_label":"unknown"}`,
      `{"tags":["gzip_magic"],"similarity_hash":"lzjd:92:...","protocol_label":"compressed_binary"}
Signal: immediate filesystem magic labeling before unpack/decompile`,
    ],
  },
  {
    id: "reel-sigma",
    label: "Sigma",
    title: "Replay: Sigma condition gating + labels",
    intervalMs: 1700,
    frames: [
      `$ cat samples/scenarios/sigma-linux-shell-command-triage/payloads.log | precursor --sigma-rule samples/scenarios/sigma-linux-shell-command-triage/sigma_rule.yml -m string -t -d --similarity-mode lzjd
{"tags":["sigma_..._keywords_0","sigma_..._keywords_6"],"sigma_rule_matches":["Suspicious Shell Commands"]}`,
      `{"tags":["sigma_..._keywords_18"],"sigma_rule_matches":["Suspicious Shell Commands"],"sigma_rule_ids":["d2bd6b47_0fe3_4eec_846d_6d657c8ee6ff"]}`,
      `Signal: Sigma intent stays portable while Precursor adds similarity + protocol context on the same stream`,
    ],
  },
];

const tabContainer = document.getElementById("scenario-tabs");
const title = document.getElementById("scenario-title");
const description = document.getElementById("scenario-description");
const command = document.getElementById("scenario-command");
const output = document.getElementById("scenario-output");
const copyButton = document.getElementById("copy-command");

function renderScenario(scenarioId) {
  const selected = scenarios.find((scenario) => scenario.id === scenarioId) || scenarios[0];
  title.textContent = selected.title;
  description.textContent = selected.description;
  command.textContent = selected.command;
  output.textContent = selected.output;
  tabContainer.querySelectorAll("button").forEach((button) => {
    button.setAttribute("aria-selected", button.dataset.scenarioId === selected.id ? "true" : "false");
  });
}

scenarios.forEach((scenario, idx) => {
  const button = document.createElement("button");
  button.type = "button";
  button.dataset.scenarioId = scenario.id;
  button.textContent = scenario.label;
  button.setAttribute("aria-selected", idx === 0 ? "true" : "false");
  button.addEventListener("click", () => renderScenario(scenario.id));
  tabContainer.appendChild(button);
});

copyButton.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(command.textContent || "");
    copyButton.textContent = "Copied";
    setTimeout(() => {
      copyButton.textContent = "Copy";
    }, 1000);
  } catch (_error) {
    copyButton.textContent = "Manual copy";
    setTimeout(() => {
      copyButton.textContent = "Copy";
    }, 1200);
  }
});

renderScenario(scenarios[0].id);

const reelTabs = document.getElementById("reel-tabs");
const reelTitle = document.getElementById("reel-title");
const reelFrame = document.getElementById("reel-frame");
const reelPlay = document.getElementById("reel-play");

let activeReel = demoReels[0];
let activeFrame = 0;
let reelTimer = null;

function stopReel() {
  if (reelTimer) {
    clearInterval(reelTimer);
    reelTimer = null;
  }
}

function drawReelFrame() {
  if (!activeReel || !reelTitle || !reelFrame) {
    return;
  }
  reelTitle.textContent = activeReel.title;
  reelFrame.textContent = activeReel.frames[activeFrame] || "";
}

function playReel() {
  if (!activeReel) {
    return;
  }
  stopReel();
  activeFrame = 0;
  drawReelFrame();
  reelTimer = setInterval(() => {
    activeFrame = (activeFrame + 1) % activeReel.frames.length;
    drawReelFrame();
  }, activeReel.intervalMs || 1600);
}

function setActiveReel(reelId) {
  const selected = demoReels.find((reel) => reel.id === reelId) || demoReels[0];
  activeReel = selected;
  activeFrame = 0;
  reelTabs.querySelectorAll("button").forEach((button) => {
    button.setAttribute("aria-selected", button.dataset.reelId === selected.id ? "true" : "false");
  });
  drawReelFrame();
  playReel();
}

if (reelTabs && reelTitle && reelFrame && reelPlay) {
  demoReels.forEach((reel, idx) => {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.reelId = reel.id;
    button.textContent = reel.label;
    button.setAttribute("aria-selected", idx === 0 ? "true" : "false");
    button.addEventListener("click", () => setActiveReel(reel.id));
    reelTabs.appendChild(button);
  });

  reelPlay.addEventListener("click", () => {
    playReel();
    reelPlay.textContent = "Replaying";
    setTimeout(() => {
      reelPlay.textContent = "Replay";
    }, 900);
  });

  setActiveReel(demoReels[0].id);
}

const statsSample = {
  "---PRECURSOR_STATISTICS---": "This JSON is output to STDERR so that you can parse stats separate from the primary output.",
  Input: {
    Count: 10,
    Unique: 10,
    AvgSize: "144",
    MinSize: 108,
    MaxSize: 387,
    P95Size: 387,
    TotalSize: "1.4KB",
  },
  Match: {
    Patterns: 5,
    TotalMatches: 28,
    Matches: [
      { Name: "http_method", Matches: 10 },
      { Name: "exploit_class_path", Matches: 9 },
      { Name: "urlencoded_jndi", Matches: 1 },
    ],
    HashesGenerated: 10,
    AvgSize: "144",
    MinSize: 108,
    MaxSize: 387,
    P95Size: 387,
    TotalSize: "1.4KB",
  },
  Compare: {
    Similarities: 45,
    AvgDistance: "51",
    MinDistance: 39,
    MaxDistance: 88,
    P95Distance: 88,
  },
  Environment: {
    SimilarityMode: "fbhash",
    RegexEngine: "pcre2",
    InputMode: "string",
    DistanceThreshold: 100,
    SinglePacketInference: true,
    SigmaRulesLoaded: 0,
  },
};

const statsBars = document.getElementById("stats-bars");
const statsJson = document.getElementById("stats-json");

function renderStatsMode() {
  if (!statsBars || !statsJson) {
    return;
  }
  const barMetrics = [
    { label: "Input Count", value: statsSample.Input.Count, max: 12 },
    { label: "Total Matches", value: statsSample.Match.TotalMatches, max: 40 },
    { label: "Hashes Generated", value: statsSample.Match.HashesGenerated, max: 12 },
    { label: "Pairwise Similarities", value: statsSample.Compare.Similarities, max: 50 },
  ];

  statsBars.innerHTML = "";
  barMetrics.forEach((metric) => {
    const row = document.createElement("div");
    row.className = "stats-bar";

    const head = document.createElement("div");
    head.className = "stats-bar-head";
    const label = document.createElement("span");
    label.textContent = metric.label;
    const value = document.createElement("strong");
    value.textContent = String(metric.value);
    head.appendChild(label);
    head.appendChild(value);

    const track = document.createElement("div");
    track.className = "stats-bar-track";
    const fill = document.createElement("div");
    fill.className = "stats-bar-fill";
    fill.style.width = `${Math.min(100, Math.round((metric.value / metric.max) * 100))}%`;
    track.appendChild(fill);

    row.appendChild(head);
    row.appendChild(track);
    statsBars.appendChild(row);
  });

  statsJson.textContent = JSON.stringify(statsSample, null, 2);
}

renderStatsMode();
