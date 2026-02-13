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
