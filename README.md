# BCM2153 reverse-engineering notes

This repository collects public-safe notes, scripts, and reproducible metadata for
researching Broadcom BCM2153 feature-phone firmware.

The immediate target sample set is a Samsung GT-B5310/B5310U firmware package
with components such as `bcmboot.img`, `boot2.img`, `amss.bin`,
`apps_compressed.bin`, DSP images, resource images, and filesystem images.

## Current model

BCM2153 should be treated as a baseband-style ARM platform used to run a
feature-phone software stack, not as the BCM21553 Android/Windows Mobile
application processor family. Public BCM2153 chip documentation is scarce, so
the main evidence source is the firmware itself.

Initial firmware strings identify:

- `Hedge Platform: BCM2153_SI1_3_43_V70`
- `BCM2153\src\irqctrl.c`
- `Nucleus PLUS - THUMB ARM Version 1.7.G1.3`
- `GT-B5310U`
- `B5310U+ZC+JH2`

## Repository policy

Do not commit raw firmware images, calibration/NVRAM data, complete extracted
strings, or long decompiler/disassembly dumps. Keep this repository focused on
scripts, offsets, hashes, short evidence snippets, and original analysis.

See [docs/publication_policy.md](docs/publication_policy.md).

## Layout

- `tools/firmware_survey.py`: read-only scanner for firmware files.
- `tools/amss_service_survey.py`: metadata-only AMSS service/debug string survey.
- `tools/amss_at_table_probe.py`: metadata-only probe for AMSS AT command dispatch records.
- `tools/amss_string_xref_probe.py`: raw multi-base xref probe for selected AMSS service strings.
- `tools/factoryfs_survey.py`: metadata-only survey for the FactoryFs FAT16 image.
- `tools/widget_package_probe.py`: bounded ZIP/manifest/entry-HTML checks without extracting or executing widget code.
- `tools/rbm_body_probe.py`: bounded RBM mode-0/1 sample expansion and explicitly tentative RGB565 previews.
- `tools/rbm_bank_survey.py`: bounded bank-wide RBM header checks and optional known-mode sample hashes.
- `tools/rbm_mode2_probe.py`: metadata-only competing mode-2 hypotheses; always unresolved, with no raster export.
- `tools/imrc_resource_index.py`: bounded logical directory lookup and RBM local-ID span validation.
- `tools/imrc_bounded_decode.py`: bounded Quram IMRC block decoder with CRC-checked PNG span extraction.
- `tests/test_imrc_bounded_decode.py`: synthetic safety regressions and optional private-sample checks.
- `tools/imrc_probe.py`: metadata-only probe for IMRC/resource-bank structure.
- `tools/imrc_public_compare.py`: metadata-only comparison against the public Quram/Imaster IMRC format model.
- `tools/ghidra_import.sh`: local-only Ghidra project builder for key images.
- `tools/ghidra_scripts/FindAmssServiceStringRefs.java`: Ghidra report for selected AMSS service-string refs.
- `tools/shpapp_ghidra_import.sh`: local-only Ghidra importer for the ShpApp embedded ELF.
- `tools/shpapp_entry_probe.py`: metadata and short disassembly probe for the ShpApp entry region.
- `tools/ghidra_scripts/ProbeShpAppHostAbi.java`: bounded Thumb analysis of the ShpApp entry, dispatcher, and host interface registration.
- `tools/ghidra_scripts/ProbeShpAppBrowserResources.java`: read-only Thumb probe of browser RBM selection and drawing calls.
- `tools/ghidra_scripts/ProbeShpAppScreenshot.java`: read-only Thumb probe of capture, descriptor-field copies, JPEG encode and screenshot file writes.
- `tools/ghidra_scripts/ProbeShpAppGraphics.java`: bounded graphics adapters and caller checks for coordinate and format candidates.
- `tools/ghidra_scripts/ProbeShpAppWidgetBindings.java`: widget API name/callback records and bounded resize/direction/event adapters.
- `tools/ghidra_scripts/ProbeShpAppWidgetEvents.java`: bounded event registration, replacement, record layout and listener-dispatch analysis.
- `tools/ghidra_scripts/ProbeShpAppWidgetListener.java`: bounded listener construction, virtual-table resolution and script-call bridge analysis.
- `tools/ghidra_scripts/ProbeShpAppEventSources.java`: bounded named-event construction, resize/focus/blur sources and beforeunload dispatch.
- `tools/ghidra_scripts/ProbeShpAppEventBridge.java`: constructed name-forwarding table slot and geometry-to-resize graphics path.
- `tools/ghidra_scripts/ProbeShpAppControlFactory.java`: registered creation entry, named control categories and ownership of geometry/event bridges.
- `docs/firmware_facts.md`: durable facts and offsets.
- `docs/amss_service_clues.md`: AMSS AT/USB/CAPI2/debug service string clues.
- `docs/system_architecture.md`: current firmware architecture map.
- `docs/reverse_engineering_plan.md`: staged investigation plan, currently focused on boot/unpacking, applications, resources, and filesystems; cellular work is deferred.
- `docs/boot_chain.md`: boot-chain hypotheses and evidence.
- `docs/bcmboot_analysis.md`: first-stage loader disassembly notes.
- `docs/shpapp_analysis.md`: Samsung ShpApp/FimBIN native ELF notes.
- `docs/shpapp_host_abi.md`: entry-to-dispatch flow and incoming/outgoing host interface observations.
- `docs/shpapp_resource_consumer.md`: browser resource callback arguments and their correspondence to indexed RBM local IDs.
- `docs/shpapp_screenshot.md`: bounded screenshot capture/descriptor/JPEG path and its limits for RBM interpretation.
- `docs/shpapp_graphics.md`: host drawing adapters, coordinate-offset observations and unresolved provider boundary.
- `docs/shpapp_widget_bindings.md`: package API names linked to native argument conversion and indirect object methods.
- `docs/shpapp_widget_events.md`: event-list record matching, replacement order and the unresolved callback/event-source boundary.
- `docs/shpapp_widget_listener.md`: constructed listener table, handleEvent/direct-call selection and the remaining event-source boundary.
- `docs/shpapp_event_sources.md`: named-event producers, two dispatch flag groups and unresolved document-receiver identity.
- `docs/shpapp_event_bridge.md`: incoming-name forwarding and a bounded graphics/geometry update that reaches resize.
- `docs/shpapp_control_factory.md`: outgoing factory slot, Browser/Widget/Messenger category byte and exposed event-name bridge.
- `docs/rbm_body_encoding.md`: observed body headers, placeholders, and validated mode-0/1 sample expansion.
- `docs/rbm_mode2_limits.md`: mode-2 framing candidates, counterexamples and image-comparison limits.
- `docs/imrc_resource_index.md`: verified named-file layout and RBM local indices.
- `docs/resource_layer.md`: IMRC/ShpApp/FactoryFs resource observations.
- `docs/factoryfs_analysis.md`: FAT16 FactoryFs directory and extension map.
- `docs/factoryfs_widgets.md`: default-widget configuration, validated package boundaries and static startup dependencies.
- `docs/ghidra_import.md`: reproducible Ghidra headless import workflow.
- `docs/tktool_tail.md`: Samsung/TkTool trailer observations.
- `docs/analysis/initial_survey.md`: manually filtered survey summary.
- `docs/research_log.md`: running research notes and milestones.
- `docs/publication_policy.md`: what is safe to publish here.
- `docs/public_references.md`: dated external references and search leads used as format context.
- `docs/tooling.md`: WSL-only workflow and local tool notes.

## First command

From WSL, with the private firmware samples in `/home/joe/thing`:

```sh
python3 tools/firmware_survey.py /home/joe/thing --out out/initial_survey
```

To create the local Ghidra project for the two first-priority ARM images:

```sh
tools/ghidra_import.sh
```

The tool writes JSON and Markdown reports to the selected output directory.
Review the generated report before copying any selected, sanitized findings into
`docs/`.
