from unittest import result
import requests
import json
import os
import base64
import hashlib
import hmac
import tempfile
import time

from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from autopkglib import Processor, ProcessorError
from azure.identity import ClientSecretCredential
from msgraph.core import GraphClient, APIVersion

__all__ = ["IntuneImporter"]

class IntuneImporter(Processor):
    """Imports a signed/notarized pkg into intune"""

    description = __doc__
    input_variables = {
        "TENANT_ID": {
            "description": "Azure tenant ID",
            "required": True,
        },
        "APPLICATION_ID": {
            "description": "Azure app ID",
            "required": True,
        },
        "APP_SECRET": {
            "description": "Generated app secret",
            "required": True,
        },
        "item_path": {
            "required": True,
            "description": "Path to a pkg or dmg to import.",
        },
        "displayname": {
            "required": True,
            "description": "App name in Intune",
        },
        "description": {
            "required": False,
            "description": "App description in Intune",
        },
        "publisher": {
            "required": True,
            "description": "App publisher in Intune",
        },
        "version": {
            "required": True,
            "description": "App version in Intune",
        },
        "build": {
            "required": True,
            "description": "App build in Intune",
        },
        "bundleID": {
            "required": True,
            "description": "App bundleID in Intune",
        },
        "privacyInformationUrl": {
            "required": False,
            "description": "App privacyInformationUrl in Intune",
        },
        "informationUrl": {
            "required": False,
            "description": "App informationUrl in Intune",
        },
        "owner": {
            "required": False,
            "description": "App owner in Intune",
        },
        "developer": {
            "required": False,
            "description": "App developer in Intune",
        },
        "notes": {
            "required": False,
            "description": "App notes in Intune",
        },
        "isFeatured": {
            "required": False,
            "description": "Enables as a featured app in Intune",
            "default": "False",
        },
        "ignoreAppVersion": {
            "required": False,
            "description": "Ignores app version",
            "default": "True",
        },
        "installAsManaged": {
            "required": False,
            "description": "Enables the app to be installed as managed",
            "default": "False",
        },
        "icon": {
            "required": False,
            "description": "Specify an icon for the app",
        }
    }
    output_variables = {
        "intune_app_changed": {"description": "True if item was imported."},
        "intune_importer_summary_result": {
            "description": "Description of interesting results."
        },
    }


    def getCredentials(self, tenant_id, application_id, application_secret):
        session = requests.Session()
        api_version=APIVersion.beta
        devicecode_credential = ClientSecretCredential(tenant_id, application_id, application_secret)
        return GraphClient(credential=devicecode_credential, api_version=api_version)


    def get(self, client, url):
        """HTTP GET request using the GraphClient"""
        return client.get(url)


    def post(self, client, url, body):
        """HTTP POST request using the GraphClient"""
        return client.post(url,
                data=json.dumps(body),
                headers={'Content-Type': 'application/json'})


    def patch(self, client, url, body):
        """HTTP POST request using the GraphClient"""
        return client.patch(url,
                data=json.dumps(body),
                headers={'Content-Type': 'application/json'})


    def getChildApp(self, bundleID, build, version):
        childApp = {}
        childApp["@odata.type"] = "#microsoft.graph.macOSLobChildApp"
        childApp["bundleId"] = bundleID
        childApp["buildNumber"] = build
        childApp["versionNumber"] = version
        return childApp


    def getIncludedApp(self, bundleID, version):
        includedApp = {}
        includedApp["@odata.type"] = "#microsoft.graph.macOSIncludedApp"
        includedApp["bundleId"] = bundleID
        includedApp["bundleVersion"] = version
        return includedApp


    def getMacOSLobApp(self, displayName, description, publisher, privacyInformationUrl, informationUrl, owner, developer, notes, fileName, bundleId, buildNumber, versionNumber, childApps, ignoreVersionDetection = True, installAsManaged = False, icon = None):
        LobApp = {}
        LobApp["@odata.type"] = "#microsoft.graph.macOSLobApp"
        LobApp["displayName"] = displayName
        LobApp["description"] = description
        LobApp["publisher"] = publisher
        LobApp["privacyInformationUrl"] = privacyInformationUrl
        LobApp["informationUrl"] = informationUrl
        LobApp["owner"] = owner
        LobApp["developer"] = developer
        LobApp["notes"] = notes
        LobApp["fileName"] = fileName
        LobApp["bundleId"] = bundleId
        LobApp["buildNumber"] = buildNumber
        LobApp["versionNumber"] = versionNumber
        LobApp["ignoreVersionDetection"] = ignoreVersionDetection
        LobApp["installAsManaged"] = installAsManaged
        LobApp["minimumSupportedOperatingSystem"] = {}
        LobApp["minimumSupportedOperatingSystem"]["@odata.type"] = "#microsoft.graph.macOSMinimumOperatingSystem"
        LobApp["minimumSupportedOperatingSystem"]["v11_0"] = True
        LobApp["childApps"] = []

        for childApp in childApps:
            LobApp["childApps"].append(childApp)

        if icon:
            LobApp["largeIcon"] = {}
            LobApp["largeIcon"]["@odata.type"] = "#microsoft.graph.mimeContent"
            LobApp["largeIcon"]["type"] = "image/png"

            with open(icon, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read())
            LobApp["largeIcon"]["value"] = encoded_string.decode('utf-8')

        return LobApp


    def getMacOSDmgApp(self, displayName, description, publisher, privacyInformationUrl, informationUrl, owner, developer, notes, fileName, bundleId, buildNumber, includedApps, ignoreVersionDetection = True, icon = None):
        DmgApp = {}
        DmgApp["@odata.type"] = "#microsoft.graph.macOSDmgApp"
        DmgApp["displayName"] = displayName
        DmgApp["description"] = description
        DmgApp["publisher"] = publisher
        DmgApp["privacyInformationUrl"] = privacyInformationUrl
        DmgApp["informationUrl"] = informationUrl
        DmgApp["owner"] = owner
        DmgApp["developer"] = developer
        DmgApp["notes"] = notes
        DmgApp["fileName"] = fileName
        DmgApp["primaryBundleId"] = bundleId
        DmgApp["primaryBundleVersion"] = buildNumber
        DmgApp["ignoreVersionDetection"] = ignoreVersionDetection
        DmgApp["minimumSupportedOperatingSystem"] = {}
        DmgApp["minimumSupportedOperatingSystem"]["@odata.type"] = "#microsoft.graph.macOSMinimumOperatingSystem"
        DmgApp["minimumSupportedOperatingSystem"]["v11_0"] = True
        DmgApp["includedApps"] = []

        for includedApp in includedApps:
            DmgApp["includedApps"].append(includedApp)
        
        if icon:
            DmgApp["largeIcon"] = {}
            DmgApp["largeIcon"]["@odata.type"] = "#microsoft.graph.mimeContent"
            DmgApp["largeIcon"]["type"] = "image/png"

            with open(icon, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read())
            DmgApp["largeIcon"]["value"] = encoded_string.decode('utf-8')

        return DmgApp


    def getMobileAppContentFile(self, filename, pkg_file, pkg_file_encr):
        mobileAppContentFile = {}
        mobileAppContentFile["@odata.type"] = "#microsoft.graph.mobileAppContentFile"
        mobileAppContentFile["name"] = filename
        mobileAppContentFile["size"] = os.path.getsize(pkg_file)
        mobileAppContentFile["sizeEncrypted"] = os.path.getsize(pkg_file_encr)
        mobileAppContentFile["manifest"] = None
        mobileAppContentFile["isDependency"] = False
        return mobileAppContentFile


    def encryptPKG(self, pkg):
        encryptionKey = os.urandom(32)
        hmacKey = os.urandom(32)
        initializationVector = os.urandom(16)
        profileIdentifier = "ProfileVersion1"
        fileDigestAlgorithm = "SHA256"

        with open(pkg, "rb") as f:
            plaintext = f.read()

        data = pad(plaintext, AES.block_size)
        cypher = AES.new(encryptionKey, AES.MODE_CBC, initializationVector)
        encrypted_data = cypher.encrypt(data)
        iv_data = initializationVector + encrypted_data
        h_mac = hmac.new(hmacKey, iv_data, hashlib.sha256).digest()
        mac = base64.b64encode(h_mac).decode()

        filebytes = Path(pkg).read_bytes()
        filehash_sha256 = hashlib.sha256(filebytes)
        fileDigest = base64.b64encode(filehash_sha256.digest()).decode()

        fileEncryptionInfo = {}
        fileEncryptionInfo["@odata.type"] = "#microsoft.graph.fileEncryptionInfo"
        fileEncryptionInfo["encryptionKey"] = base64.b64encode(encryptionKey).decode()
        fileEncryptionInfo["macKey"] = base64.b64encode(hmacKey).decode()
        fileEncryptionInfo["initializationVector"] = base64.b64encode(initializationVector).decode()
        fileEncryptionInfo["profileIdentifier"] = profileIdentifier
        fileEncryptionInfo["fileDigestAlgorithm"] = fileDigestAlgorithm
        fileEncryptionInfo["fileDigest"] = fileDigest
        fileEncryptionInfo["mac"] = mac
        return (h_mac + iv_data, fileEncryptionInfo)


    def findVersion(self, version, test_list):
        for element in test_list:
            if element.get('primaryBundleVersion'):
                if element['primaryBundleVersion'] == version:
                    return True
            if element.get('versionNumber'):
                if element['versionNumber'] == version:
                    return True
        return False


    def getContendFromReuqestResult(self, result):
        content_json = result._content.decode('utf8').replace("'", '"').replace("(\"", '(\\"').replace("\")", '\\")')
        return json.loads(content_json)

    def main(self):
        TENANT_ID = self.env.get("TENANT_ID")
        APPLICATION_ID = self.env.get("APPLICATION_ID")
        APP_SECRET = self.env.get("APP_SECRET")
        RECIPE_CACHE_DIR = self.env.get("RECIPE_CACHE_DIR")
        item_path = self.env.get("item_path")

        item_filename = Path(item_path).name
        title = self.env.get("displayname")
        description = self.env.get("description", "")
        publisher = self.env.get("publisher")
        version = self.env.get("version")
        build = self.env.get("build")
        bundleID = self.env.get("bundleID")
        privacyInformationUrl = self.env.get("privacyInformationUrl", "")
        informationUrl = self.env.get("informationUrl", "")
        owner = self.env.get("owner", "")
        developer = self.env.get("developer", "")
        notes = self.env.get("notes", "Imported by AutoPkg")
        ignoreAppVersion = self.env.get("ignoreAppVersion", True)
        installAsManaged = self.env.get("installAsManaged", False)
        isFeatured = self.env.get("isFeatured", False)
        icon = self.env.get("icon")
        childApps = []

        if item_filename.endswith(".pkg"):
            #create childapps
            childApps.append(self.getChildApp(bundleID, build, version))
            #create lobapp
            macOSLobApp = self.getMacOSLobApp(title, description, publisher, privacyInformationUrl, informationUrl, owner, developer, notes, item_filename, bundleID, build, version, childApps, ignoreAppVersion, installAsManaged, icon)
    
        if item_filename.endswith(".dmg"):
            includedApps = []
            includedApps.append(self.getIncludedApp(bundleID, version))
            #create lobapp
            macOSLobApp = self.getMacOSDmgApp(title, description, publisher, privacyInformationUrl, informationUrl, owner, developer, notes, item_filename, bundleID, version, includedApps, ignoreAppVersion, icon)

        #get credentials
        credentials = self.getCredentials(TENANT_ID, APPLICATION_ID, APP_SECRET)
        
        #/deviceAppManagement/mobileApps?$filter=(isof("microsoft.graph.macOSLobApp"))&$search=
        mobildeapp_result = self.get(credentials, '/deviceAppManagement/mobileApps?$search=' + title)
        contentApps = self.getContendFromReuqestResult(mobildeapp_result)
        if self.findVersion(version, contentApps["value"]):
            self.env["intune_app_changed"] = False
            self.output(f'{title + " " + version} already exists')
            return
        
        #create intune app
        macOSLobApp_result = self.post(credentials, '/deviceAppManagement/mobileApps', macOSLobApp)
        if macOSLobApp_result.status_code != 201:
            raise ProcessorError("ERROR: creating mobileApp failed. Status code - " + str(macOSLobApp_result.status_code))
        
        #get app ID
        content = self.getContendFromReuqestResult(macOSLobApp_result)
        appID = content['id']

        url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.macOSLobApp/contentVersions'
        contentVersions_result = self.post(credentials, url, {})
        if contentVersions_result.status_code != 201:
            raise ProcessorError("ERROR: creating contentVersions failed. Status code - " + contentVersions_result.status_code)

        contentVersions = self.getContendFromReuqestResult(contentVersions_result)
        contentVersionsID = contentVersions['id']

        # encrypt file
        encrypted_data, fileEncryptionInfo = self.encryptPKG(item_path)
        new_file, filename = tempfile.mkstemp(dir=RECIPE_CACHE_DIR)
        with open(new_file, "wb") as binary_file:
            # Write bytes to file
            binary_file.write(encrypted_data)

        # get mobileAppContentFile
        mobileAppContentFile = self.getMobileAppContentFile(item_filename, item_path, filename)

        # get content version file
        files_url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.macOSLobApp/contentVersions/' + contentVersionsID + '/files'
        files_result = self.post(credentials, files_url, mobileAppContentFile)
        if files_result.status_code != 201:
            raise ProcessorError("ERROR: creating contentVersionsFiles failed. Status code - " + str(files_result.status_code))

        files_content = self.getContendFromReuqestResult(files_result)
        files_contentID = files_content['id']
        files_url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.macOSLobApp/contentVersions/' + contentVersionsID + '/files/' + files_contentID
        
        attempts = 40
        while attempts > 0:
            file = self.get(credentials, files_url)
            file_content = self.getContendFromReuqestResult(file)
            if file_content["uploadState"] == "azureStorageUriRequestSuccess":
                break
            if file_content["uploadState"] == "azureStorageUriRequestFailed":
                raise ProcessorError("ERROR: azureStorageUriRequestFailed failed")

            time.sleep(5)
            attempts-=1

        if file_content["uploadState"] != "azureStorageUriRequestSuccess":
            raise ProcessorError("ERROR: File request did not complete in the allotted time.")

        # create blocklist
        azureStorageUri = file_content["azureStorageUri"]
        chunk_size=6*1024*1024
        headers = {
            'x-ms-blob-type': 'BlockBlob'
        }
        block_ids = []
        index = 0
        with open(filename, "rb") as stream:
            while True:
                read_data = stream.read(chunk_size)
                if read_data == b'':
                    break
                id = "block-" + format(index, "04")
                
                block_id = base64.b64encode(id.encode()).decode()
                block_ids.append(block_id)
                uri = azureStorageUri + "&comp=block&blockid=" + block_id    
                r = requests.put(uri, headers=headers, data=read_data.decode('iso-8859-1'))
                index += 1
        
        headers = {'Content-Type': 'application/xml'}   
        uri = azureStorageUri + "&comp=blocklist"
        xml = """<?xml version="1.0" encoding="utf-8"?><BlockList>"""
        for id in block_ids:
            xml += "<Latest>" + id + "</Latest>"
        xml += """</BlockList>"""
        
        # upload block list
        r = requests.put(uri, headers=headers, data=xml)
        
        # clean up
        os.unlink(filename)

        # commit file
        commitData = {}
        commitData["fileEncryptionInfo"] = fileEncryptionInfo
        commitFileUri = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.macOSLobApp/contentVersions/' + contentVersionsID + '/files/' + files_contentID + "/commit"
        commitFile_result = self.post(credentials, commitFileUri, commitData)
        if commitFile_result.status_code != 200:
            raise ProcessorError("ERROR: commitFile failed. Status code - " + str(commitFile_result.status_code))

        files_url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.macOSLobApp/contentVersions/' + contentVersionsID + '/files/' + files_contentID
        attempts = 40
        while attempts > 0:
            file = self.get(credentials, files_url)
            file_content = self.getContendFromReuqestResult(file)
            if file_content["uploadState"] == "commitFileSuccess":
                break
            if file_content["uploadState"] == "commitFileFailed":
                raise ProcessorError("ERROR: commitFileFailed failed")

            time.sleep(5)
            attempts-=1

        if file_content["uploadState"] != "commitFileSuccess":
            raise ProcessorError("ERROR: commitFileFailed request did not complete in the allotted time.")

        commitAppBody = {}
        commitAppBody["@odata.type"] = "#microsoft.graph.macOSLobApp"
        commitAppBody["committedContentVersion"] = contentVersionsID

        files_url = '/deviceAppManagement/mobileApps/' + appID
        commitApp_result = self.patch(credentials, files_url, commitAppBody)
        if commitApp_result.status_code != 204:
            raise ProcessorError("ERROR: commitApp failed. Status code - " + str(commitApp_result.status_code))

        time.sleep(5)

        self.env["intune_app_changed"] = True
        self.env["title"] = title
        self.env["version"] = version
        self.env["intune_importer_summary_result"] = {
            "summary_text": "The following new items were imported into Intune:",
            "report_fields": [
                "name",
                "version",
                "appID",
                "installed_as_managed",
                "ignore_app_version",
            ],
            "data": {
                "name": title,
                "version": version,
                "appID": appID,
                "installed_as_managed": installAsManaged,
                "ignore_app_version": ignoreAppVersion,
            },
        }
        self.output(f'Uploaded: {self.env["title"] + " " + self.env["version"]}')

if __name__ == "__main__":
    PROCESSOR = IntuneImporter()
    PROCESSOR.execute_shell()
