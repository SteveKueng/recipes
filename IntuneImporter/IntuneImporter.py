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
        "pkg_path": {
            "required": True,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_displayname": {
            "required": True,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_description": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_publisher": {
            "required": True,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_version": {
            "required": True,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_build": {
            "required": True,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_bundleID": {
            "required": True,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_privacyInformationUrl": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_informationUrl": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_owner": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_developer": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_notes": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
        },
        "pkg_isFeatured": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
            "default": "False",
        },
        "pkg_ignoreAppVersion": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
            "default": "True",
        },
        "pkg_installAsManaged": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
            "default": "False",
        },
        "pkg_icon": {
            "required": False,
            "description": "Path to a pkg or dmg to import.",
        }
    }
    output_variables = {
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


    def getMacOSLobApp(self, displayName, description, publisher, privacyInformationUrl, informationUrl, owner, developer, notes, fileName, bundleId, buildNumber, versionNumber, childApps, isFeatured = False, ignoreVersionDetection = True, installAsManaged = False):
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
        LobApp["isFeatured"] = isFeatured
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

        return LobApp


    def getMobileAppContentFile(self, pkg_filename, pkg_file, pkg_file_encr):
        mobileAppContentFile = {}
        mobileAppContentFile["@odata.type"] = "#microsoft.graph.mobileAppContentFile"
        mobileAppContentFile["name"] = pkg_filename
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


    def getContendFromReuqestResult(self, result):
        content_json = result._content.decode('utf8').replace("'", '"').replace("(\"", '(\\"').replace("\")", '\\")')
        return json.loads(content_json)

    def main(self):
        TENANT_ID = self.env.get("TENANT_ID")
        APPLICATION_ID = self.env.get("APPLICATION_ID")
        APP_SECRET = self.env.get("APP_SECRET")
        RECIPE_CACHE_DIR = self.env.get("RECIPE_CACHE_DIR")
        pkg_path = self.env.get("pkg_path")

        pkg_filename = Path(pkg_path).name
        pkg_title = self.env.get("pkg_displayname")
        pkg_description = self.env.get("pkg_description", "")
        pkg_publisher = self.env.get("pkg_publisher")
        pkg_version = self.env.get("pkg_version")
        pkg_build = self.env.get("pkg_build")
        pkg_bundleID = self.env.get("pkg_bundleID")
        pkg_privacyInformationUrl = self.env.get("pkg_privacyInformationUrl", "")
        pkg_informationUrl = self.env.get("pkg_informationUrl", "")
        pkg_owner = self.env.get("pkg_owner", "")
        pkg_developer = self.env.get("pkg_developer", "")
        pkg_notes = self.env.get("pkg_notes", "Imported by AutoPkg")
        pkg_ignoreAppVersion = self.env.get("pkg_ignoreAppVersion", True)
        pkg_installAsManaged = self.env.get("pkg_installAsManaged", False)
        pkg_isFeatured = self.env.get("pkg_isFeatured", False)
        pkg_icon = self.env.get("pkg_icon")
        childApps = []

        #create childapps
        childApps.append(self.getChildApp(pkg_bundleID, pkg_build, pkg_version))
        #create lobapp
        macOSLobApp = self.getMacOSLobApp(pkg_title, pkg_description, pkg_publisher, pkg_privacyInformationUrl, pkg_informationUrl, pkg_owner, pkg_developer, pkg_notes, pkg_filename, pkg_bundleID, pkg_build, pkg_version, childApps, pkg_isFeatured, pkg_ignoreAppVersion, pkg_installAsManaged)
        #get credentials
        credentials = self.getCredentials(TENANT_ID, APPLICATION_ID, APP_SECRET)
        #create intune app
        mobildeapp_result = self.post(credentials, '/deviceAppManagement/mobileApps', macOSLobApp)
        if mobildeapp_result.status_code != 201:
            raise ProcessorError("ERROR: creating mobileApp failed. Status code - " + str(mobildeapp_result.status_code))
        
        #get app ID
        content = self.getContendFromReuqestResult(mobildeapp_result)
        appID = content['id']

        url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.macOSLobApp/contentVersions'
        contentVersions_result = self.post(credentials, url, {})
        if contentVersions_result.status_code != 201:
            raise ProcessorError("ERROR: creating contentVersions failed. Status code - " + contentVersions_result.status_code)

        contentVersions = self.getContendFromReuqestResult(contentVersions_result)
        contentVersionsID = contentVersions['id']

        # encrypt file
        encrypted_data, fileEncryptionInfo = self.encryptPKG(pkg_path)
        new_file, filename = tempfile.mkstemp(dir=RECIPE_CACHE_DIR)
        with open(new_file, "wb") as binary_file:
            # Write bytes to file
            binary_file.write(encrypted_data)

        # get mobileAppContentFile
        mobileAppContentFile = self.getMobileAppContentFile(pkg_filename, pkg_path, filename)

        # get content version file
        files_url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.macOSLobApp/contentVersions/' + contentVersionsID + '/files'
        files_result = self.post(credentials, files_url, mobileAppContentFile)
        if files_result.status_code != 201:
            raise ProcessorError("ERROR: creating contentVersionsFiles failed. Status code - " + str(files_result.status_code))

        files_content = self.getContendFromReuqestResult(files_result)
        files_contentID = files_content['id']
        files_url = '/deviceAppManagement/mobileApps/' + appID + '/microsoft.graph.macOSLobApp/contentVersions/' + contentVersionsID + '/files/' + files_contentID
        
        attempts = 20
        while attempts > 0:
            file = self.get(credentials, files_url)
            file_content = self.getContendFromReuqestResult(file)
            if file_content["uploadState"] == "azureStorageUriRequestSuccess":
                break
            if file_content["uploadState"] == "azureStorageUriRequestFailed":
                raise ProcessorError("ERROR: azureStorageUriRequestFailed failed")

            time.sleep(10)
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
        attempts = 20
        while attempts > 0:
            file = self.get(credentials, files_url)
            file_content = self.getContendFromReuqestResult(file)
            if file_content["uploadState"] == "commitFileSuccess":
                break
            if file_content["uploadState"] == "commitFileFailed":
                raise ProcessorError("ERROR: commitFileFailed failed")

            time.sleep(10)
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

        self.env["munki_importer_summary_result"] = {
            "summary_text": "The following new items were imported into Intune:",
            "report_fields": [
                "name",
                "version",
                "appID",
                "installed_as_managed",
                "ignore_app_version",
            ],
            "data": {
                "name": pkg_title,
                "version": pkg_version,
                "appID": appID,
                "installed_as_managed": pkg_installAsManaged,
                "ignore_app_version": pkg_ignoreAppVersion,
            },
        }

if __name__ == "__main__":
    PROCESSOR = IntuneImporter()
    PROCESSOR.execute_shell()
