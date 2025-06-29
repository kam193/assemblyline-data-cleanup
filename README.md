# Preprocessing data for AssemblyLine

This repository contains a set of data cleaning* & processing to ensure they are integrated as
much as possible with AssemblyLine, as well as some small additional datasets.

*Occasionally, some data may cause troubles in AL update process. They are removed if possible.

## Yara rules

AssemblyLine expects YARA rules to follow [CCCS-Yara](https://github.com/CybercentreCanada/CCCS-Yara?tab=readme-ov-file)
format and integrates the best with metadata prepared in that way.

This repository attempts automatically fill key missing data (categories, malware names) in the following Yara rulesets:

  * https://github.com/YARAHQ/yara-forge/

Cleaned and enriched data are automatically put in the releases:

  * `cleaned-rules.yar` - cleaned and enriched Yara-forge "extended" set, kept under this name for
    backward compatibility
  * `yara-forge-extended-enriched.yar` - cleaned and enriched Yara-forge "extended" set
  * `yara-forge-extended-unenriched.yar` - cleaned but not enriched Yara-forge "extended" set

Note that first two are lacking comments (e.g. full license text) from the original dataset. Thus they
are shipped together with unenriched form where you can find all additional details.
