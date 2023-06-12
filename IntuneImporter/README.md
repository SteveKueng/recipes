# IntuneImporter

https://blog.ikueng.ch/2023/03/21/microsoft-intune-and-autopkg/

## Description

Imports pkgs and dmgs in Microsoft Intune.

## additional python requirements

For the processor to work, additional Python modules must be installed first. This can be done with the following command:

```console
sudo /Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/pip3 install -r requirements.txt

```

## Configure global settings

## Input Variables

- **TENANT\_ID:**
  - **required:** True
  - **description:** Azure tenant ID
- **APPLICATION\_ID:**
  - **required:** True
  - **description:** Azure app ID
- **APP\_SECRET:**
  - **required:** True
  - **description:** Generated app secret
- **item\_path:**
  - **required:** True
  - **description:** Path to a dmg or pkg
- **displayname:**
  - **required:** True
  - **description:** App name in Intune (visible to the user)
- **description:**
  - **required:** False
  - **description:** App description in Intune
- **publisher:**
  - **required:** True
  - **description:** App publisher in Intune
- **version:**
  - **required:** True
  - **description:** App version in Intune
- **build:**
  - **required:** True
  - **description:** App build in Intune
- **bundleID:**
  - **required:** True
  - **description:** App bundleID in Intune
- **privacyInformationUrl:**
  - **required:** False
  - **description:** App privacyInformationUrl in Intune
- **informationUrl:**
  - **required:** False
  - **description:** App informationUrl in Intune
- **owner:**
  - **required:** False
  - **description:** App owner in Intune
- **developer:**
  - **required:** False
  - **description:** App developer in Intune
- **notes:**
  - **required:** False
  - **description:** App notes in Intune
- **isFeatured:**
  - **required:** False
  - **description:** Enables as a featured app in Intune
- **ignoreAppVersion:**
  - **required:** False
  - **description:** Ignores app version
  - **default** True
- **installAsManaged:**
  - **required:** False
  - **description:** Enables the app to be installed as managed
  - **default** False
- **icon:**
  - **required:** False
  - **description:** Specify an icon for the app

## Output Variables

- **intune_app_changed:**
  - **description:** True if item was imported.
- **intune_importer_summary_result:**
  - **description:** Description of interesting results.
