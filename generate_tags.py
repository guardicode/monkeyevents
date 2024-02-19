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

# End parameters


def retrieve_mitre_data(url):
    print("Attempting download of Mitre data, please wait...")
    response = requests.get(url)
    if response.status_code == 200:
        print("\nDownload finished!")
    else:
        print("Error: ", response.status_code)
    return json.loads(response.content)


def reformat_technique(target_technique):
    #
    # This function reformats the given technique from the mitre dataset to conform
    # to the specs of monkeyevents.
    #
    # param target_technique dict - technique object from the mitre dataset
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


def technique_fits_project_scope(target_technique):
    # This check validates whether the given technique fits the scope of the project
    # For example, it is an attack technique, it is not deprecated or revoked,
    # and whether any of the technique's indicated platforms match the project
    if (
        technique.get("type") == "attack-pattern" and
        not technique.get("x_mitre_deprecated") and
        not technique.get("revoked") and
        any(platform in technique.get("x_mitre_platforms", []) for platform in included_platforms)
    ):
        return True
    else:
        return False


mitre_dataset = retrieve_mitre_data(mitre_source)

valid_techniques = []
for technique in mitre_dataset.get("objects", []):
    if technique_fits_project_scope(technique):
        reformatted_technique = reformat_technique(technique)
        designation = f'"attack-{technique["external_references"][0]["external_id"]}"'
        valid_techniques.append(f"{reformatted_technique}_TAG = {designation}")

output = "\n".join(valid_techniques) + "\n"
filepath = "monkeyevents/tags/attack.py"

with open(filepath, "w") as file:
    file.write(output)

print("New attack.py file generated!")
