import json
from pathlib import Path
from typing import Collection, Iterable

import requests

# This script loads the enterprise-attack.json MITRE dataset into a dict (MITRE_dataset)
# according to the parameters set below. The dict is then iterated to produce an attack.py
# file, containing variables for the multiple MITRE ATT&CK tags relevant to the project.
#
# The enterprise-attack.json file is sourced from MITRE's repository at
# https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack.


def main(mitre_source: str, included_platforms: Collection[str], output_path: Path):
    mitre_dataset = retrieve_mitre_data(mitre_source)

    valid_techniques = []
    for technique in mitre_dataset.get("objects", []):
        if technique_fits_project_scope(technique):
            reformatted_technique = reformat_technique(technique)
            designation = f'"attack-{technique["external_references"][0]["external_id"]}"'
            valid_techniques.append(f"{reformatted_technique}_TAG = {designation}")

    valid_techniques.sort(key=lambda t: t.split(" = ")[1])

    write_tags_to_file(valid_techniques, output_path)


def retrieve_mitre_data(url):
    print("Attempting download of MITRE data, please wait...")
    response = requests.get(url)
    response.raise_for_status()

    if response.status_code == 200:
        print("\nDownload finished!")

    return json.loads(response.content)


def technique_fits_project_scope(target_technique):
    # This check validates whether the given technique fits the scope of the project
    # For example, it is an attack technique, it is not deprecated or revoked,
    # and whether any of the technique's indicated platforms match the project
    if (
        target_technique.get("type") == "attack-pattern"
        and not target_technique.get("x_mitre_deprecated")
        and not target_technique.get("revoked")
        and any(
            platform in target_technique.get("x_mitre_platforms", [])
            for platform in included_platforms
        )
    ):
        return True

    return False


def reformat_technique(target_technique):
    #
    # This function reformats the given technique from the MITRE dataset to conform
    # to the specs of monkeyevents.
    #
    # param target_technique dict - technique object from the MITRE dataset
    # returns a specially-formatted string to suit the specs of monkeyevents
    #
    return (
        "_".join(
            [
                target_technique["name"].upper().replace(" ", "_"),
                target_technique["external_references"][0]["external_id"].upper(),
            ]
        )
        .replace("-", "_")
        .replace(".", "_")
        .replace("/", "_")
        .replace("(", "")
        .replace(")", "")
        .replace("Ä", "A")
    )


def write_tags_to_file(tags: Iterable[str], output_path: Path):
    # This function writes the tags to a file
    output = "\n".join(tags) + "\n"

    with open(output_path, "w") as file:
        file.write(output)

    print("New attack.py file generated!")


if __name__ == "__main__":
    mitre_source = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack-14.1.json"
    )
    included_platforms = ["Containers", "Linux", "Network", "PRE", "Windows"]
    output_path = Path("monkeyevents/tags/attack.py")

    main(mitre_source, included_platforms, output_path)
