# Preprocessing data for AssemblyLine

This repository contains a set of data cleaning* & processing to ensure they are integrated as
much as possible with AssemblyLine, as well as some small additional datasets.

*Occasionally, some data may cause troubles in AL update process. They are removed if possible.

## Yara rules

AssemblyLine expects YARA rules to follow [CCCS-Yara](https://github.com/CybercentreCanada/CCCS-Yara?tab=readme-ov-file)
format and integrates the best with metadata prepared in that way.

This repository attempts automatically fill key missing data (categories, malware names) in the following Yara rulesets:

  * https://github.com/YARAHQ/yara-forge/
  * https://github.com/elastic/protections-artifacts/

Cleaned and enriched data are automatically put in the releases:

  * `cleaned-rules.yar` - cleaned and enriched Yara-forge "extended" set, kept under this name for
    backward compatibility
  * `yara-forge-extended-enriched.yar` - cleaned and enriched Yara-forge "extended" set
  * `yara-forge-extended-unenriched.yar` - cleaned but not enriched Yara-forge "extended" set

Note that first two are lacking comments (e.g. full license text) from the original dataset. Thus they
are shipped together with unenriched form where you can find all additional details.

  * `elastic-protections-artifacts-enriched.yar` - enriched Yara rules from the Elastic
    [protection-artifacts](https://github.com/elastic/protections-artifacts/)
    repository. Note that they are licensed under Elastic's own [license](https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt)

## Adding to AssemblyLine

To keep up to date, add the URL linking to the latest release file as your YARA update source:
`https://github.com/kam193/assemblyline-data-cleanup/releases/latest/download/<filename>`, e.g.:
`https://github.com/kam193/assemblyline-data-cleanup/releases/latest/download/yara-forge-extended-enriched.yar`