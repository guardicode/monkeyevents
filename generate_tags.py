import json

import requests

# This script loads the enterprise-attack.json mitre dataset into a dict (mitre_dataset)
# according to the parameters set below. The dict is then iterated to produce an attack.py
# file, containing variables for the multiple Mitre ATT&CK tags relevant to the project.
#
# The enterprise-attack.json file is sourced from Mitre's repository at
# https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack.

# Replace the URL below with the version of your choice.

mitre_source = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-14.1.json"
)

# Begin parameters; modify these to customize the tags produced by the script

included_platforms = ["Windows", "Linux"]
include_subtechniques = True
include_deprecated = False  # include techniques marked as "deprecated"
include_revoked = False  # include techniques marked as "revoked"

# End parameters


def retrieve_mitre_data(url):
    print("Attempting download of Mitre data, please wait...")
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("\nDownload finished!")
            return json.loads(response.content)
        else:
            print("Error: ", response.status_code)
            return None
    except requests.RequestException as e:
        print("Error: ", e)
        return None


def reformat_technique(target_technique):
    #
    # This function reformats the given technique from the mitre dataset to conform
    # to the specs of monkeyevents.
    #
    # param target_technique dict - technique object from the mitre dataset
    # returns a specially-formatted string to suit the specs of monkeyevents
    #
    output_reformatted_technique = (
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
    return output_reformatted_technique


mitre_dataset = retrieve_mitre_data(mitre_source)
if mitre_dataset:
    valid_techniques = []
    for technique in mitre_dataset.get("objects", []):
        if technique.get("type") == "attack-pattern":
            x_mitre_platforms = technique.get("x_mitre_platforms", [])
            x_mitre_is_subtechnique = technique.get("x_mitre_is_subtechnique", False)
            x_mitre_deprecated = technique.get("x_mitre_deprecated", False)
            revoked = technique.get("revoked", False)

            checks = {
                "platforms": any(platform in x_mitre_platforms for platform in included_platforms),
                "subtechnique": x_mitre_is_subtechnique == include_subtechniques
                or not include_subtechniques,
                "deprecated": x_mitre_deprecated == include_deprecated or not include_deprecated,
                "revoked": revoked == include_revoked or not include_revoked,
            }

            if all(checks.values()):
                reformatted_technique = reformat_technique(technique)
                designation = f'"attack-{technique["external_references"][0]["external_id"]}"'
                valid_techniques.append(f"{reformatted_technique}_TAG = {designation}")

    output = "\n".join(valid_techniques) + "\n"
    filepath = "monkeyevents/tags/attack.py"

    with open(filepath, "w") as file:
        file.write(output)

    print("New attack.py file generated!")
else:
    print("Failed to generate attack.py :(")
