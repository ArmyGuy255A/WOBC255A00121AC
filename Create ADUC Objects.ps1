$topLevelOUName = "1BCT101AB"
$topLevelIMOSecurityGroupName = "Brigade IMOs"
$childOUNames = @("S1", "S2", "S3", "S4", "S6", "CMD-GRP")
$grandchildOUNames = @("Computers", "Users", "Groups")
$securityGroupNames = @("Users", "IMOs")

$deleteMode = $false

$Domain = Get-ADDomain

#Delete everything created above
if ($deleteMode -eq $true) {
    $topLevelOU = Get-ADOrganizationalUnit -Filter ('Name -eq "{0}"' -f $topLevelOUName)
    $allChildrenOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $topLevelOU.DistinguishedName
    $allChildrenOUs | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $false

    Get-ADUSer -Filter * -SearchBase $topLevelOU.DistinguishedName | Remove-ADUser -Confirm:$false
    Get-ADGroup -Filter * -SearchBase $topLevelOU.DistinguishedName | Remove-ADGroup -Confirm:$false
    Get-ADComputer -Filter * -SearchBase $topLevelOU.DistinguishedName | Remove-ADComputer -Confirm:$false

    #Delete the Parent OU
    $topLevelOU | Remove-ADOrganizationalUnit -Recursive -Confirm:$false


} else {
    #Create the top-level OU
    $topLevelOU = New-ADOrganizationalUnit -Name $topLevelOUName -PassThru

    #Create the top-level IMO security group
    $topLevelIMOGroup = New-ADGroup -Name $topLevelIMOSecurityGroupName -Path $topLevelOU.DistinguishedName -GroupCategory Security -GroupScope Global -PassThru

    #Then, create the child OUs
    foreach ($childOUName in $childOUNames) {
        $childOU = New-ADOrganizationalUnit -Name $childOUName -Path $topLevelOU.DistinguishedName -PassThru

        ##Create the grandchild OUs
        foreach ($grandchildOUName in $grandchildOUNames) {
            $grandchildOU = New-ADOrganizationalUnit -Name $grandchildOUName -Path $childOU.DistinguishedName -PassThru

            if ($grandchildOUName -eq "Computers") {
                ###If we created the Computers OU, then create the computer objects...
                1..5 | ForEach-Object {New-ADComputer -Name ("{0}COMPUTER{1:000}" -f $childOUName,$_).Replace("-","")  -Path $grandchildOU.DistinguishedName}

            } elseif ($grandchildOUName -eq "Users") {
                ###If we created the Users OU, then create the user objects...

                ##Normal Users
                $password = "P@`$`$W0rd" | ConvertTo-SecureString -AsPlainText -Force
                1..5 | ForEach-Object {
                    $displayName = ("{0} User{1:00}" -f $childOUName,$_).Replace("-","")
                    $firstName = $childOUName
                    $lastName = ("User{0:00}" -f $_)
                    $samAccountName = $displayName.Trim().Replace(" ", "_").ToLower()
                    $userPrincipalName = ("{0}@{1}" -f $samAccountName, $Domain.Forest)
                    New-ADUSer `
                        -Name $displayName `
                        -Path $grandchildOU.DistinguishedName `
                        -SamAccountName $samAccountName `
                        -UserPrincipalName $userPrincipalName `
                        -AccountPassword $password `
                        -DisplayName $displayName `
                        -GivenName $firstName `
                        -Surname $lastName `
                        -Enabled $true
                }

                ##IMO User
                1..1 | ForEach-Object {
                    $displayName = ("{0} IMO{1:00}" -f $childOUName,$_).Replace("-","")
                    $firstName = $childOUName
                    $lastName = ("IMO{0:00}" -f $_)
                    $samAccountName = $displayName.Trim().Replace(" ", "_").ToLower()
                    $userPrincipalName = ("{0}@{1}" -f $samAccountName, $Domain.Forest)
                    New-ADUSer `
                        -Name $displayName `
                        -Path $grandchildOU.DistinguishedName `
                        -SamAccountName $samAccountName `
                        -UserPrincipalName $userPrincipalName `
                        -AccountPassword $password `
                        -DisplayName $displayName `
                        -GivenName $firstName `
                        -Surname $lastName `
                        -Enabled $true `
                        -Department "IMO"
                }

            } elseif ($grandchildOUName -eq "Groups") {
                ###If we created the Groups OU, then create the group objects...
                foreach ($securityGroupName in $securityGroupNames) {
                    $groupName = ("{0} {1}" -f $childOUName,$securityGroupName)
                    $group = New-ADGroup -Name $groupName -GroupCategory Security -GroupScope Global -Path $grandchildOU.DistinguishedName -PassThru 

                    ####Add in the users to the appropriate security groups
                    if ($securityGroupName.Contains("User")) {
                        $users = Get-ADUser -Filter 'Name -like "*User*"' -SearchBase $childOU.DistinguishedName
                        Add-ADGroupMember -Identity $group.SamAccountName -Members $users
                    } elseif ($securityGroupName.Contains("IMO")) {
                        $imos = Get-ADUser -Filter 'Name -like "*IMO*"' -SearchBase $childOU.DistinguishedName
                        Add-ADGroupMember -Identity $group.SamAccountName -Members $imos
                        if ($childOUName.Equals("S6")) {
                            ####If the group is S6-IMOs, then add it to the top-level IMO security group
                            Add-ADGroupMember -Identity $topLevelIMOGroup.SamAccountName -Members $group
                        }
                    }
                }
            } else {
                #If we added more OUs... then maybe do something else...
            }            
        }
    }
}