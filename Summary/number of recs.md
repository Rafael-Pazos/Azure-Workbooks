securityresources
 | where type == "microsoft.security/assessments"
 // Get recommendations in useful format
 | project
	['TenantID'] = tenantId,
	['SubscriptionID'] = subscriptionId,
	['AssessmentID'] = name,
	['DisplayName'] = properties.displayName,
	['ResourceType'] = tolower(split(properties.resourceDetails.Id,"/").[7]),
	['ResourceName'] = tolower(split(properties.resourceDetails.Id,"/").[8]),
	['ResourceGroup'] = resourceGroup,
	['ContainsNestedRecom'] = tostring(properties.additionalData.subAssessmentsLink),
	['StatusCode'] = properties.status.code,
	['StatusDescription'] = properties.status.description,
	['PolicyDefID'] = properties.metadata.policyDefinitionId,
	['Description'] = properties.metadata.description,
	['RecomType'] = properties.metadata.assessmentType,
	['Remediation'] = properties.metadata.remediationDescription,
	['RemediationEffort'] = properties.metadata.implementationEffort,
	['Severity'] = properties.metadata.severity,
	['Categories'] = properties.metadata.categories,
	['UserImpact'] = properties.metadata.userImpact,
	['Threats'] = properties.metadata.threats,
	['Link'] = properties.links.azurePortal
    // summarize and order
 | summarize count() by tostring(Severity)
 | order by count_



 Number of HIGH, MEDIUM and LOW Recommendations

 Resources
| where tags.owner != ""
| project tags.owner