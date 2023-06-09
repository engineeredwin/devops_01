param(
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $targetServer,

   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $requestType,

 [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $VEDServer ,

   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $certParentDN,

   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $certCommonName,

   [Parameter(Mandatory=$true)]
 [string]
   $certCADN,

   #[Parameter(Mandatory=$true)]
 #[ValidateNotNullOrEmpty()]
   #$certCSRFile,

 [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $username,

   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $password,

   [Parameter(Mandatory=$false)]
 [ValidateNotNullOrEmpty()]
 [bool]
   $apply_cert = $False
)


#########################################################################################
# Change these options to suit your environment
#########################################################################################

# How noisy should we be?
$showScriptVerbose = $true
$showRestMethodVerbose = $true

# Ignore certificate errors encountered while connecting to REST web service
$ignoreCertWarnings = $false

#########################################################################################
# Modification below here shouldn't be required
#########################################################################################
#########################################################################################
#########################################################################################
#########################################################################################
# Check Prerequisites & Configure options
#########################################################################################
#region preprocess
# Make sure we are using PS version 3.0 or greater
if ($PSVersionTable.PSVersion.Major -lt 3) {
 Write-Host "Version 3.0 of Windows Powershell is required for this script to run."
 return -1
}

if ($showScriptVerbose) {
  $verbosePreference = "Continue"
} else {
  $verbosePreference = "SilentlyContinue"
}

if ($ignoreCertWarnings) {
   [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
}

#endregion preprocess
#########################################################################################
# Functions
#########################################################################################
#region functions


function Connect-VEDService {
<#
.SYNOPSIS
 Initializes a connection to Venafi TPP WebSDK, and returns PSObject with API Key,
   URI, and Valid Until properties that can be used for future WebSDK calls.
.PARAMETER server
   The FQDN server name to connect to. (When using SSL, this should match the CN/SAN
   on the certificate used, or SSL errors will prevent connection!)
.PARAMETER credential
   A PSCredential object that contains a valid username/password for connecting
.PARAMETER port
   The port used to connect. Default 443.
.PARAMETER useSSL
   Whether or not to use SSL for connection. Default true.
.OUTPUTS
   PSObject containing VTPP WebSDK API Key, Valid Until date, and BaseURI.
   { APIKey = [NoteProperty]; ValidUntil = [NoteProperty]; BaseURI = [NoteProperty] }
#>
 param(
   [Parameter(Mandatory=$false, Position=0)]
   [ValidateNotNullOrEmpty()]
   [string]
   $VEDServer ,
   [Parameter(Mandatory=$false, Position=1)]
   [ValidateNotNullOrEmpty()]
   [System.Management.Automation.PSCredential]
   $credential,
   [Parameter(Mandatory=$false, Position=2)]
   [int]
   $port=443,
   [Parameter(Mandatory=$false, Position=3)]
   [bool]
   $useSSL=$true
 )

   # Build base URI first.
 $baseURI = ""
 if ($useSSL) {
       $baseURI = "https://"
   } else {
       $baseURI = "http://"
   }
 #$baseURI += "$($VEDServer ):$($port)/vedsdk"
   $baseURI = "https://xxx.com/vedsdk"



   # Get string values for username / password, convert to JSON
   $user = $credential.GetNetworkCredential().username
 $pass = $credential.GetNetworkCredential().password
 $json = @{ Username = $user;  Password = $pass; } | ConvertTo-JSON

   # Try to call the WebSDK Authorize method
   try {
       # This will throw an error if unable to connect for any reason!
       $response = Invoke-RestMethod -Uri "$($baseURI)/Authorize" -Body $json -Method POST -ContentType 'application/json' -Verbose:$showRestMethodVerbose

     Write-Verbose "Got VED API Key: $response"

       if ($response.APIKey -eq $null -or $response.ValidUntil -eq $null) {
         throw "An Error Occurred Attempting to Authenticate to the WebSDK"
       }
   } catch {
       Write-Host -ForegroundColor Red "ERROR: Unable to connect to WebSDK.`n`t$($_)"
       return $null
   }

   #Create a brand-new object to hold the connection information for reuse
   $objConnection = [PSCustomObject]@{
     APIKey = $response.APIKey
     ValidUntil = $response.ValidUntil
     BaseURI = $baseURI
   }

 return $objConnection

}

function Get-VEDDNExists {
<#
.SYNOPSIS
 Given a DN to a policy or certificate object
.OUTPUT
  Returns object referenced by the DN if it exists, and null otherwise
#>
 param (
   [Parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]
   [string]
   $strDN,
   [Parameter(Mandatory=$true, Position=0)]
   [ValidateNotNullOrEmpty()]
   [object]
   $VEDConnection
 )

 if ($VEDConnection.ValidUntil -eq $null -or $VEDConnection.ValidUntil -lt (Get-Date)) {
   throw "Provided VED connection is no longer valid!"
 }

   # API call checks if the DN of the policy exist
   $uri = $VEDConnection.baseURI + '/Config/isvalid'
 $json = @{ObjectDN=$strDN} | ConvertTo-JSON

 $results = Invoke-RestMethod -Uri $uri -Body $json -Method POST -ContentType 'application/json' -Headers @{"X-Venafi-Api-Key" = $VEDConnection.APIKey} -Verbose:$showRestMethodVerbose

 if ($results.Result -eq 1 -and $results.Object -ne $null) {
   # Success
   return $results.Object
 }

   Write-Verbose "No object found with DN $($strDN)"
 return $null
}

function Get-VEDConfigAttribute {
<#
.SYNOPSIS
 Given a DN to an object and a valid attribute name, returns the value of that
   attribute.
.PARAMETER strDN
   DN of object to query
.PARAMETER attribute
   Attribute name to reference
.PARAMETER VEDConnection
   Object that contains API Key and BaseURI to connect to WebSDK. Returned from Connect-VEDService
.OUTPUTS
   Values contained within attribute parameter
#>
 param (
   [Parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]
   [string]
   $strDN,
   [Parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]
   [string]
   $attribute,
   [Parameter(Mandatory=$true, Position=0)]
   [ValidateNotNullOrEmpty()]
   [object]
   $VEDConnection
 )

 if ($VEDConnection.ValidUntil -eq $null -or $VEDConnection.ValidUntil -lt (Get-Date).ToUniversalTime()) {
   throw "Provided VED connection is no longer valid!"
 }

   # API call will not be successful if DN is not accurate or if the attribute does not exist
 $uri = $VEDConnection.baseURI + '/Config/Read'
 $json = @{ObjectDN=$strDN; AttributeName=$attribute; } | ConvertTo-JSON
 $results = Invoke-RestMethod -Uri $uri -Body $json -Method POST -ContentType 'application/json' -Headers @{"X-Venafi-Api-Key" = $VEDConnection.APIKey} -Verbose:$showRestMethodVerbose

 if ($results.Result -eq 1 -and $results.Values -ne $null) {
   # Success
   return $results.Values
 }

   # Failure
 return $null
}

function Create-VEDCertificate {
<#
.SYNOPSIS
 Creates a certificate object
#>
 param (
   [Parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]
   [string]
   $name,
   [Parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]
   [string]
   $parent,
       [Parameter(Mandatory=$true)]
   [string]
   $subject,
       [Parameter(Mandatory=$true)]
   [string]
   $CA,
   [Parameter(Mandatory=$true, Position=0)]
   [ValidateNotNullOrEmpty()]
   [object]
   $VEDConnection,
       [Parameter(Mandatory=$true)]
   [string]
   $CSR
 )

 if ($VEDConnection.ValidUntil -eq $null -or $VEDConnection.ValidUntil -lt (Get-Date)) {
   throw "Provided VED connection is no longer valid!"
 }

   if ((Get-VEDDNExists -strDN $parent -VEDConnection $VEDConnection) -eq $null) {
       throw "Create-VEDCertificate: specified parent DN does not exist: $($parent)"
   }

   # Build DN of certificate object
   $strDN = $parent + "\" + $name

   $existingObject = Get-VEDDNExists -strDN $strDN -VEDConnection $VEDConnection

   if ($existingObject) {
       throw "Create-VEDCertificate: specified common name already exists: $($name)"
   }

   # API call starts a immediate signing request of an existing certificate object with a new CSR
   # The API call will fail if the certificate object is not in an "OK" status
 $uri = $VEDConnection.baseURI + '/Certificates/Request'
 $json = @{PolicyDN=$parent; ObjectName=$name; CADN = $CA; PKCS10 = $CSR} | ConvertTo-JSON
   $results = Invoke-RestMethod -Uri $uri -Body $json -Method POST -ContentType 'application/json' -Headers @{"X-Venafi-Api-Key" = $VEDConnection.APIKey}  -Verbose:$showRestMethodVerbose

 if ($results.CertificateDN -ne $null) {
   # Success
   return $results.CertificateDN
 }

 return $null
}

function Confirm-VEDCertificate {
<#
.SYNOPSIS
 Confirm that a certificate was successfully issued

   REFERENCED: https://s/hc/en-us/community/posts/208985698-How-to-check-the-status-of-a-certificate-via-API
#>
 param (
   [Parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]
   [string]
   $name,
   [Parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]
   [string]
   $parent,
   [Parameter(Mandatory=$true, Position=0)]
   [ValidateNotNullOrEmpty()]
   [object]
   $VEDConnection
 )

 if ($VEDConnection.ValidUntil -eq $null -or $VEDConnection.ValidUntil -lt (Get-Date)) {
   throw "Confirm-VEDCertification: Provided VED connection is no longer valid!"
 }

   if ((Get-VEDDNExists -strDN $parent -VEDConnection $VEDConnection) -eq $null) {
       throw "Confirm-VEDCertification: specified parent DN does not exist $($parent)"
   }

   # Build DN of the certificate object
   $strDN = $parent + "\" + $name

   # Do-While loop checks if the certificate object is still processing the renewal
   # The certificate object will either go to an "OK" status or an Error status
   do {
       $workValue = Get-VEDConfigAttribute -strDN $strDN -attribute "Work To Do" -VEDConnection $VEDConnection

       if ($workValue -eq "1") {
           Start-Sleep -s 5
       }

   } While ($workValue -eq "1")

   # Checks if the certificate object went into an error status
   $errorValue = Get-VEDConfigAttribute -strDN $strDN -attribute "In Error" -VEDConnection $VEDConnection

   if ($errorValue -eq "1") {
      return $null
   }

   $certVaultValue = Get-VEDConfigAttribute -strDN $strDN -attribute "Certificate Vault Id" -VEDConnection $VEDConnection

   if ($certVaultValue -eq $null) {
      return $null
   }

   return $certVaultValue

}

function Get-VEDCertificate {
<#
.SYNOPSIS
 Gets a certificate object
.OUTPUT
   Certificate data in a Base64 format if successful; otherwise NULL is returned
#>
 param (
   [Parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]
   [string]
   $name,
   [Parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]
   [string]
   $parent,
   [Parameter(Mandatory=$true, Position=0)]
   [ValidateNotNullOrEmpty()]
   [object]
   $VEDConnection
 )

 if ($VEDConnection.ValidUntil -eq $null -or $VEDConnection.ValidUntil -lt (Get-Date)) {
   throw "Provided VED connection is no longer valid!"
 }

   #Build the DN of the certificate object
   $strDN = $parent + "\" + $name

   # Check if the certificate object exists
   $existingObject = Get-VEDDNExists -strDN $strDN -VEDConnection $VEDConnection

   if ($existingObject -eq $null) {
       throw "Get-VEDObject: invalid parent DN and/or certificate name!"
   }

   $uri = $VEDConnection.baseURI + '/Certificates/Retrieve'
 $json = @{CertificateDN = "$parent\$name"; Format = "Base64"} | ConvertTo-JSON
   $results = Invoke-RestMethod -Uri $uri -Body $json -Method POST -ContentType 'application/json' -Headers @{"X-Venafi-Api-Key" = $VEDConnection.APIKey} -Verbose:$showRestMethodVerbose

 if ($results.CertificateData -ne $null) {
   # Success
   return $results.CertificateData
 }

   # Failed to return certificate data
 return $null
}

function request-cert {
param(
 [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $VEDServer ,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $certParentDN,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $certCommonName,
   [Parameter(Mandatory=$true)]
 [string]
   $certCADN,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
   [string]
   $certCSRFile,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [System.Management.Automation.PSCredential]
 $credential
)

   # If we've already got a credential object from before, let's use it!
   if ($credential -eq $null -or $credential.GetType().Name -ne "PSCredential" ) {
       $credential = Get-Credential -message "Enter a user with access to VED WebSDK"
   }

   # Connect and get a key
   $service = Connect-VEDService  -VEDServer $VEDServer  -credential $credential

   if ($service -eq $null) {
       Write-Host -ForegroundColor Red "ERROR: Unable to connect to Venafi TPP REST API (WebSDK)!"
       return
   }

   try {
       if ($certCADN -eq $null -or $certCADN -eq "" -or -not $(Get-VEDDNExists -strDN $certCADN -VEDConnection $service)) {
           Write-Host -ForegroundColor Red "Unable to determine valid CA Template to use"
           return $null
       }

       $csr = Get-Content $certCSRFile | out-string
       $certDN = Create-VEDCertificate -name $certCommonName -parent $certParentDN -CA $certCADN -subject $certCommonName -VEDConnection $service  -csr $CSR
   } catch {
       Write-Host -ForegroundColor Red "ERROR: Failed to create certificate. Message: $($_)"
       return $null;
   }

   if ($certDN -ne $null -and $certDN -ne "") {

       # Confirm status is "OK"
       $certVaultID = Confirm-VEDCertificate -name $certCommonName -parent $certParentDN -VEDConnection $service

       if ($certVaultID -ne $null) {

           $object = [PSCustomObject]@{
             CertDN = $certDN;
               certVaultID = $certVaultID
           }

           $object

       } else {

           $strDN = $certParentDN + "\" + $certCommonName

           $statusValue = Get-VEDConfigAttribute -strDN $strDN -attribute "Status" -VEDConnection $service

           Write-Host -ForegroundColor Red "ERROR: Certificate in an unexpected status. Status: " $statusValue
           return
       }
   }
   else
   {
       Write-Host -ForegroundColor Red "ERROR: Failed to create certificate!"
       return $null
   }
}

function Renew-VEDCertificate {
<#
.SYNOPSIS
	Renew a certificate object
#>
	param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$name,
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[string]
		$parent,
        [Parameter(Mandatory=$true)]
		[string]
		$subject,
		[Parameter(Mandatory=$true, Position=0)]
		[ValidateNotNullOrEmpty()]
		[object]
		$VEDConnection,
        [Parameter(Mandatory=$true)]
		[string]
		$CSR
	)
    


	if ($VEDConnection.ValidUntil -eq $null -or $VEDConnection.ValidUntil -lt (Get-Date)) {
		throw "Provided VED connection is no longer valid!"
	}

    if ((Get-VEDDNExists -strDN $parent -VEDConnection $VEDConnection) -eq $null) {
        throw "Renew-VEDCertificate: specified parent DN does not exist $($parent)"
    }

    # Build DN of certificate object
    $strDN = $parent + "\" + $name
    
    $existingObject = Get-VEDDNExists -strDN $strDN -VEDConnection $VEDConnection

    if ($existingObject -eq $null) {
        throw "Renew-VEDCertificate: specified common name does not exist $($name)"
    }

    # API call strats an immediate renewal of an existing certificate object with a new CSR
    # The API call will fail if the certificate object is not in an "OK" status
	$uri = $VEDConnection.baseURI + '/Certificates/Renew'
	$json = @{CertificateDN=$strDN; PKCS10 = $CSR} | ConvertTo-JSON
    $results = Invoke-RestMethod -Uri $uri -Body $json -Method POST -ContentType 'application/json' -Headers @{"X-Venafi-Api-Key" = $VEDConnection.APIKey} -Verbose:$showRestMethodVerbose
    
	if ($results.Success -eq $true) {
		# Success
		return $strDN
	}
	
    # Failure
	return $null

}

function renew-cert {
param(
 [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $VEDServer ,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $certParentDN,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $certCommonName,
   [Parameter(Mandatory=$true)]
 [string]
   $certCADN,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
   [string]
   $certCSRFile,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [System.Management.Automation.PSCredential]
 $credential
)

   # If we've already got a credential object from before, let's use it!
   if ($credential -eq $null -or $credential.GetType().Name -ne "PSCredential" ) {
       $credential = Get-Credential -message "Enter a user with access to VED WebSDK"
   }

   # Connect and get a key
   $service = Connect-VEDService  -VEDServer $VEDServer  -cre $cre

   if ($service -eq $null) {
       Write-Host -ForegroundColor Red "ERROR: Unable to connect to Venafi TPP REST API (WebSDK)!"
       return
   }

   try {
       if ($certCADN -eq $null -or $certCADN -eq "" -or -not $(Get-VEDDNExists -strDN $certCADN -VEDConnection $service)) {
           Write-Host -ForegroundColor Red "Unable to determine valid CA Template to use"
           return $null
       }

       $csr = Get-Content $certCSRFile | out-string
       $certDN = Renew-VEDCertificate -name $certCommonName -parent $certParentDN -subject $certCommonName -VEDConnection $service  -csr $CSR
   } catch {
       Write-Host -ForegroundColor Red "ERROR: Failed to renew certificate. Message: $($_)"
       return $null;
   }

   if ($certDN -ne $null -and $certDN -ne "") {

       # Confirm status is "OK"
       $certVaultID = Confirm-VEDCertificate -name $certCommonName -parent $certParentDN -VEDConnection $service

       if ($certVaultID -ne $null) {

           $object = [PSCustomObject]@{
             CertDN = $certDN;
               certVaultID = $certVaultID
           }

           $object

       } else {

           $strDN = $certParentDN + "\" + $certCommonName

           $statusValue = Get-VEDConfigAttribute -strDN $strDN -attribute "Status" -VEDConnection $service

           Write-Host -ForegroundColor Red "ERROR: Certificate in an unexpected status. Status: " $statusValue
           return
       }
   }
   else
   {
       Write-Host -ForegroundColor Red "ERROR: Failed to create certificate!"
       return $null
   }
}

function download-cert {
param(
 [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $VEDserver,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $certParentDN,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [string]
   $certCommonName,
   [Parameter(Mandatory=$false)]
 [string]
   $certCADN,
   [Parameter(Mandatory=$true)]
 [ValidateNotNullOrEmpty()]
 [System.Management.Automation.PSCredential]
 $credential

)

   # Connect and get a key
   $service = Connect-VEDService  -VEDServer $VEDserver -credential $credential

   if ($service -eq $null) {
       Write-Host -ForegroundColor Red "ERROR: Unable to connect to Venafi TPP REST API (WebSDK)!"
       return
   }


   # Attempts to pull certificate with the provide information
   try {
       $certData = Get-VEDCertificate -name $certCommonName -parent $certParentDN -VEDConnection $service
   } catch {
       Write-Host -ForegroundColor Red "ERROR: Failed to get certificate. Message: $($_)"
       return $null;
   }

   # If successful format certifiate
   if ($certData -ne $null -and $certData -ne "") {

       # Added 3/3/17 to encode certificate so it can be opened through the crypto
       # shell extension (same as how certs are saved from Venafi manually)

       $codedCertData = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($certData))
       $object = [PSCustomObject]@{
           CertData = $codedCertData
       }

       return $object
   }
   else
   {
       Write-Host -ForegroundColor Red "ERROR: Failed to get certificate!"
       return $null
   }

}

function apply-cert {
  param([Parameter(Mandatory=$true)] [ValidateNotNullOrEmpty()]  [string]$filePath)

   Import-Certificate -FilePath $filePath -CertStoreLocation "Cert:\LocalMachine\MY"
}

#endregion functions

#####################################################################################
## Main Code
#####################################################################################

# We need this for https connecitons
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::TLS12

# Pre Work - Download Root Certs
$CertPath = "D:\b\Bin\Certificates"
$RootCert = "$CertPath\a.crt"
Invoke-WebRequest -Uri "http://crl.com/pki/NM%20Root%20CA2.crt" -OutFile $RootCert

# Pre Work - Install Root Certs
$CertStoreLocation = "Cert:\LocalMachine\Root"
Import-Certificate -FilePath $RootCert -CertStoreLocation $CertStoreLocation

# Pre Work - Setup
[System.Security.SecureString]$password = ConvertTo-SecureString -String $password -AsPlainText -Force
$credential = new-object -typename System.Management.Automation.PSCredential -argumentlist @($username,$pa)

# Generate csr
$certCSRFile = "$CertPath\$targetServer.csr"
$Command = "certreq.exe -f -new $CertPath\request.inf $CertPath\$targetServer.csr"
Invoke-Expression -Command $Command


switch ( $requestType ) {

   "create" {
       request-cert -VEDServer $VEDServer  -certParentDN $certParentDN -certCommonName $certCommonName -certCADN $certCADN -CertCSRFile $certCSRFile -cre $cre
       $signedCert = download-cert -VEDServer $VEDServer  -certParentDN $certParentDN -certCommonName $certCommonName -certCADN $certCADN -credential $cre
           $signedCert.certData | out-file -FilePath "$CertPath\$targetServer.cer"
       if ($apply_cert) {
           apply-cert -filePath "$CertPath\$targetServer.cer"
       }
       break;
   }
   "renew" {
       renew-cert -VEDServer $VEDServer  -certParentDN $certParentDN -certCommonName $certCommonName -certCADN $certCADN -CertCSRFile $certCSRFile -cre $cre
       $signedCert = download-cert -VEDServer $VEDServer  -certParentDN $certParentDN -certCommonName $certCommonName -certCADN $certCADN -credential $cre
           $signedCert.certData | out-file -FilePath "$CertPath\$targetServer.cer"
       if ($apply_cert) {
           apply-cert -filePath "$CertPath\$targetServer.cer"
       }
       break;
   }
}

