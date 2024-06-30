#####################################################################
#####       Funciones básicas para el uso de Prisma Cloud       #####
#####       con su REST API a través de PowerShell              #####
#####################################################################


function New-PrismaCloudLogin{

    param(
        #String with the username ID
        [Parameter(
        Mandatory=$true,
        ValueFromPipeline=$true)]
        [Alias('user','name')]
        [String]
        $Username,

        #String with the password
        [Parameter(Mandatory=$true,
        ValueFromPipeline=$true)]
        [Alias('pass','pwd')]
        [String]
        $PassID
        )
$PrismaLogin = @{
    Uri = "$URI"+"login"
    Method = "POST"
    Body = @{username=$Username;password=$PassID} | ConvertTo-Json
    Headers = @{"charset"="UTF-8";"content-type"="application/json"}
}
$response=Invoke-RestMethod @PrismaLogin -Verbose
return $response.token
}



function Set-PrismaCloudURI {
    param(
        [Parameter(
            Mandatory=$false,
            HelpMessage="Introduce a valid token in String format",
            ValueFromPipeline=$true)]
            [String]
            $URL
        )
    #Choose URI from condensed URL
    switch ($URL) {
        "app.eu"            { $URI = "https://api4.prismacloud.io/" }
        "app2.eu"           { $URI = "https://api2.eu.prismacloud.io/"}
        "app.prismacloud"   { $URI = "https://api.prismacloud.io/"}
        "app2.prismacloud"  { $URI = "https://api2.prismacloud.io/"}
        Default {$URI = "https://api4.prismacloud.io/"}
    }
    
    #Sets the URI as a global variable
    $global:URI = $URI

    
}


function Export-PrismaCloudAlertResolvedLastMonth {
 
    param (
    [Parameter(
    Mandatory=$true,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $Token,
    
    [Parameter(
    Mandatory=$false,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $CloudAccount,
    
    [Parameter(
    Mandatory=$false,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $CloudType,

    [Parameter(
    Mandatory=$false,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $CloudRegion,
    
    [Parameter(
    Mandatory=$true,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $AccountGroup,
    
    [Parameter(
    Mandatory=$false,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $ComplianceStandard,

    
    [Parameter(
    Mandatory=$true,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    [ValidateSet('critical','high','medium','low','informational')]
    $Severity,

    [Parameter(
        Mandatory=$false,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [DateTime]
        $AlertLastUpdate = (Get-Date).AddMonths(-1)  # Parámetro opcional para AlertLastUpdate con valor predeterminado al mes pasado
   

    )
    

    $HttpValueCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

    $HttpValueCollection.Add("timeType","relative")
    $HttpValueCollection.Add("timeAmount","1")
    $HttpValueCollection.Add("timeUnit","year")
    $HttpValueCollection.Add("detailed","false")
    $HttpValueCollection.Add("alert.status","resolved")
    $HttpValueCollection.Add("policy.severity","$Severity")
    
    
    if ($PSBoundParameters.ContainsKey('CloudAccount')){
        $HttpValueCollection.Add("cloud.account","$CloudAccount")
    }
    
    if ($PSBoundParameters.ContainsKey('CloudType')){
        $HttpValueCollection.Add("cloud.type","$CloudType")
    }
    
    if ($PSBoundParameters.ContainsKey('AccountGroup')){
        $HttpValueCollection.Add("account.group","$AccountGroup")
    }
    
    if ($PSBoundParameters.ContainsKey('Compliancestandard')){
        $HttpValueCollection.Add("policy.complianceStandard","$ComplianceStandard")
    }
    
    
    
    $HttpValueCollection
    
    $Query=[System.UriBuilder]("$("$URI" + "alert")")
    $Query.Query =$HttpValueCollection.ToString()

    $PrismaReportList = @{
        Uri = $Query.Uri
        Method= "GET"
        Headers= @{"x-redlock-auth"= $token;"Accept"= "application/json";"charset"="UTF-8";"content-type"="application/json"}
    }
       
    
    $Result = @()


    $EpochStart = Get-Date 1970-01-01T00:00:00

    $invoked=Invoke-RestMethod @PrismaReportList -Verbose

    
    $invoked | ForEach-Object {
        $AlertLastUpdateEpoch = $EpochStart.AddMilliseconds($_.lastUpdated)
        if ($AlertLastUpdateEpoch -ge $AlertLastUpdate -and $AlertLastUpdateEpoch -lt (Get-Date)){
            if (($($EpochStart.AddMilliseconds($_.lastSeen))) -ge $AlertLastUpdate){
                    $policy=Get-PrismaCloudPolicyById -Token $token -Id $_.PolicyID            
                    $result += New-Object PSObject -Property @{
                        AlertId = $_.id
                        AlertResolvedReason = $_.reason
                        AlertLastUpdate = $($EpochStart.AddMilliseconds($_.lastUpdated))
                        ResourceName = $_.resource.name
                        AccountNameOfResource = $_.resource.account
                        AlertFirstSeen = $($EpochStart.AddMilliseconds($_.firstSeen))
                        AlertLastSeen = $($EpochStart.AddMilliseconds($_.lastSeen))
                        Policy= $policy.name
                    
            
            }
            }
        }
    } 
    $result | Select-Object AlertId, AlertResolvedReason, AlertLastUpdate, `
        ResourceName, AccountNameOfResource, AlertFirstSeen, AlertLastSeen, Policy `
        | Export-Csv  -Path "$($AccountGroup.Split('_')[0])_$($Severity.ToUpper())_PrismaCloudAlertsResolvedLastMonth.csv" -NoTypeInformation
}
function Get-PrismaCloudPolicyById{
    
    param (
        #String with the JWT token
        [Parameter(
        Mandatory=$true,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [String]
        $Token,
        
        [Parameter(
        Mandatory=$true,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [String]
        $Id
    )

    $PrismaPolicyID = @{
        Uri = "$URI" + "policy/" + "$Id"
        Method= "GET"
        Headers= @{"x-redlock-auth"= $token;"Accept"= "application/json";"charset"="UTF-8";"content-type"="application/json"}
        }

    $response = Invoke-RestMethod @PrismaPolicyID -Verbose


    return $response
}
function Export-PrismaCloudAlert {
    
    param (
    [Parameter(
    Mandatory=$true,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $Token,
    
    [Parameter(
    Mandatory=$false,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $CloudAccount,
    
    [Parameter(
    Mandatory=$false,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $CloudType,

    [Parameter(
    Mandatory=$false,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $CloudRegion,
    
    [Parameter(
    Mandatory=$true,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $AccountGroup,
    
    [Parameter(
    Mandatory=$false,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $ComplianceStandard,

    
    [Parameter(
    Mandatory=$true,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    [ValidateSet('critical','high','medium','low','informational')]
    $Severity
    )
    

    $HttpValueCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)

    $HttpValueCollection.Add("timeType","relative")
    $HttpValueCollection.Add("timeAmount","1")
    $HttpValueCollection.Add("timeUnit","year")
    $HttpValueCollection.Add("detailed","false")
    $HttpValueCollection.Add("alert.status","open")
    $HttpValueCollection.Add("policy.severity","$Severity")
    
    
    if ($PSBoundParameters.ContainsKey('CloudAccount')){
        $HttpValueCollection.Add("cloud.account","$CloudAccount")
    }
    
    if ($PSBoundParameters.ContainsKey('CloudType')){
        $HttpValueCollection.Add("cloud.type","$CloudType")
    }
    
    if ($PSBoundParameters.ContainsKey('AccountGroup')){
        $HttpValueCollection.Add("account.group","$AccountGroup")
    }
    
    if ($PSBoundParameters.ContainsKey('Compliancestandard')){
        $HttpValueCollection.Add("policy.complianceStandard","$ComplianceStandard")
    }
    
    
    
    $HttpValueCollection
    
    $Query=[System.UriBuilder]("$("$URI" + "alert")")
    $Query.Query =$HttpValueCollection.ToString()

    $PrismaReportList = @{
        Uri = $Query.Uri
        Method= "GET"
        Headers= @{"x-redlock-auth"= $token;"Accept"= "application/json";"charset"="UTF-8";"content-type"="application/json"}
    }
       
    
    $Result = @()


    $EpochStart = Get-Date 1970-01-01T00:00:00

    $invoked=Invoke-RestMethod @PrismaReportList -Verbose
    
    $invoked | ForEach-Object{
            $policy=Get-PrismaCloudPolicyById -Token $token -Id $_.PolicyID
            $result +=  New-Object PSObject -Property @{
                AlertId = $_.id
                ResourceName = $_.resource.name
                AccountNameOfResource = $_.resource.account
                ResourceId = $_.resource.accountId
                AlertFirstSeen = $($EpochStart.AddMilliseconds($_.firstSeen))
                AccountGroup = $AccountGroup 
                Policy= $policy.name
                Severity = $Severity

            }
        }
    
    $result | Select-Object AlertId, `
            ResourceName,AccountNameOfResource,ResourceId,AlertFirstSeen, AccountGroup, Policy, Severity `
    | Export-Csv  -Path "$($AccountGroup.Split('_')[0])_$($Severity.ToUpper())_PrismaCloudAlerts.csv" -NoTypeInformation
}

function Get-PrismaCloudComplianceTrend{
    param (
        
        #String with the JWT token
        [Parameter(
        Mandatory=$true,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [String]
        $Token,
        
        
        [Parameter(
        Mandatory=$true,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [string]
        $TimeAmount,
        
        [Parameter(
        Mandatory=$true,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [ValidateSet("minute", "hour", "day", "week", "month","year")]
        [string]
        $TimeUnit,

        [Parameter(
        Mandatory=$false,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [String]
        $CloudAccount,
        
        [Parameter(
        Mandatory=$false,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [String]
        $CloudType,

        [Parameter(
        Mandatory=$false,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [String]
        $GroupBy="cloud.type",

        [Parameter(
        Mandatory=$false,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [String]
        $CloudRegion,
        
        [Parameter(
        Mandatory=$false,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [String]
        $AccountGroup,
        
        [Parameter(
        Mandatory=$false,
        HelpMessage="Introduce a valid token in String format",
        ValueFromPipeline=$true)]
        [String]
        $ComplianceStandard
        
    
    )

$HttpValueCollection = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)


if ($PSBoundParameters.ContainsKey('CloudAccount')){
    $HttpValueCollection.Add("cloud.account","$CloudAccount")
}

if ($PSBoundParameters.ContainsKey('CloudType')){
    $HttpValueCollection.Add("cloud.type","$CloudType")
}

if ($PSBoundParameters.ContainsKey('CloudRegion')){
    $HttpValueCollection.Add("cloud.region","$CloudRegion")
}


if ($PSBoundParameters.ContainsKey('AccountGroup')){
    $HttpValueCollection.Add("account.group","$AccountGroup")
}


if ($PSBoundParameters.ContainsKey('Compliancestandard')){
    $HttpValueCollection.Add("policy.complianceStandard","$ComplianceStandard")
}

$HttpValueCollection.Add("timeType","relative")

$HttpValueCollection.Add("timeAmount","$TimeAmount")

$HttpValueCollection.Add("timeUnit","$TimeUnit")

$HttpValueCollection.add("groupBy","$GroupBy")


$Query=[System.UriBuilder]("$("$URI" + "compliance/posture/trend")")
$Query.Query =$HttpValueCollection.ToString()

$PrismaReportList = @{
    Uri = $Query.Uri
    Method= "GET"
    Headers= @{"x-redlock-auth"= $token;"Accept"= "application/json";"charset"="UTF-8";"content-type"="application/json"}
}

return Invoke-RestMethod @PrismaReportList -Verbose

}


function Export-PrismaCloudMonthlyComplianceReport{
    param (
        
    #String with the JWT token
    [Parameter(
    Mandatory=$true,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [String]
    $Token,
    
    [Parameter(
    Mandatory=$true,
    HelpMessage="Introduce a valid token in String format",
    ValueFromPipeline=$true)]
    [string]
    $AccountGroup,

    [Parameter(
    Mandatory=$false,
    HelpMessage="Introduce a valid token in Boolean format",
    ValueFromPipeline=$true)]
    [bool]
    $Detailed=$false
    )

    #Set UNIX time start
    $EpochStart= Get-Date "1970-01-01T00:00:00"
    
    
    $Negocio=@()
    $Negocio+=Get-PrismaCloudComplianceTrend -Token $token -TimeAmount "4" -TimeUnit "month" -AccountGroup $AccountGroup -ComplianceStandard "CIS Controls v8"
    
    if ($Detailed) {   
        $Negocio| ForEach-Object {
            $_|ForEach-Object{
            $RepoHash = New-Object psobject -Property @{
                Fecha = ($EpochStart.AddMilliseconds($_.timestamp))
                Recursos_Fallidos = $_.failedResources
                Recursos_Correctos= $_.passedResources
                Recursos_Totales = $_.totalResources
                Recursos_ConAlertasAltas = $_.highSeverityFailedResources
                Recursos_ConAlertasMedias = $_.mediumSeverityFailedResources
                Recursos_ConAlertasBajas = $_.lowSeverityFailedResources
                Recursos_ConAlertasCriticas = $_.criticalSeverityFailedResources
                Recursos_ConAlertasInfo = $_.informationalSeverityFailedResources
                Porcentaje_Recursos_Correctos = if ($_.totalResources -ne 0){$_.passedResources/$_.totalResources} else {0}
                Porcentaje_Recursos_Alertas_Criticas = if ($_.totalResources -ne 0){$_.criticalSeverityFailedResources/$_.totalResources} else {0}
                Porcentaje_Recursos_Alertas_Altas= if ($_.totalResources -ne 0){$_.highSeverityFailedResources/$_.totalResources} else {0}
                Porcentaje_Recursos_Alertas_Medias= if ($_.totalResources -ne 0){$_.mediumSeverityFailedResources/$_.totalResources} else {0}
                Porcentaje_Recursos_Alertas_Bajas= if ($_.totalResources -ne 0){$_.lowSeverityFailedResources/$_.totalResources} else {0}
                Porcentaje_Recursos_Alertas_Info= if ($_.totalResources -ne 0){$_.informationalSeverityFailedResources/$_.totalResources} else {0}
            }
        $RepoHash `
        | Export-Csv -Path "DetailedMonthlyComplianceRepo_$AccountGroup.csv" -Append
        }
        }
        }
    else{
        $Negocio| ForEach-Object {
            $_|ForEach-Object{ 
            $RepoHash = New-Object psobject -Property @{
                Fecha = ($EpochStart.AddMilliseconds($_.timestamp))
                Pass= $_.passedResources
                Total = $_.totalResources
                "%Pass" = if ($_.totalResources -ne 0){$_.passedResources/$_.totalResources} else {0}
                "%Critical" = if ($_.totalResources -ne 0){$_.criticalSeverityFailedResources/$_.totalResources} else {0}
                "%High" = if ($_.totalResources -ne 0){$_.highSeverityFailedResources/$_.totalResources} else {0}
                "%Medium"= if ($_.totalResources -ne 0){$_.mediumSeverityFailedResources/$_.totalResources} else {0}
                "%Low"= if ($_.totalResources -ne 0){$_.lowSeverityFailedResources/$_.totalResources} else {0}
                "%Info"= if ($_.totalResources -ne 0){$_.informationalSeverityFailedResources/$_.totalResources} else {0}
            }
        $RepoHash `
        | Export-Csv -Path "$AccountGroup.csv" -Append -NoTypeInformation 
        }
    }
    }

}