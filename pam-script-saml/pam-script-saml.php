#!/usr/bin/env php
<?php
# pam-script-saml
# SAML2 Assertion Check for pam-script
#
# $PAM_USER - contains the username
# $PAM_AUTHTOK - contains (hopefully) a SAML assertion
# $PAM_RHOST - remote host
# $PAM_TYPE - contains the type of the PAM request (only auth supported)
#
# Parameters:
#  - userid=<attribute> (uid)
#  - grace=<seconds> (600)
#  - saml_check_timeframe=[0/1] (1)
#  - idp=<metadata_path>
#  - trusted_sp=<entityID> {Assertion/Conditions/AudienceRestriction/Audience}
#  - only_from=<ip>

// init autoloader
include 'vendor/autoload.php';

// only auth requests
if(empty($_SERVER['PAM_TYPE']) || $_SERVER['PAM_TYPE'] !== 'auth')
{
	echo 'This PAM module only supports the "auth" type.'.PHP_EOL;
	exit(1);
}

// get necessary ENV variables
$pamUser = $_SERVER['PAM_USER'];
$xmlSrc = $_SERVER['PAM_AUTHTOK'];
$remoteHost = $_SERVER['PAM_RHOST'];

// stop here if the "assertion" is less than or equal 32 chars (that can't be a XML doc)
if(strlen($xmlSrc) <= 32)
{
	echo 'No valid Assertion given: Document too short'.PHP_EOL;
	exit(3);
}

// get arguments
$args = array_merge(array(
	'userid' => 'uid',
	'grace' => '600',
	'saml_check_timeframe' => '1',
	//'only_from' => '127.0.0.1,::1',
), array_reduce(array_slice($argv, 1), function($res, $item) {
	list($opt, $val) = explode('=', $item, 2);
	$opt = preg_replace('/^(\'(.*)\'|"(.*)")$/', '$2$3', $opt);
	$val = preg_replace('/^(\'(.*)\'|"(.*)")$/', '$2$3', $val);
	if(in_array($opt, array('idp', 'trusted_sp')))
	{
		if(!isset($res[$opt])) $res[$opt] = array();
		$res[$opt][] = $val;
	}
	else
	{
		$res[$opt] = $val;
	}
	return $res;
}, array()));

// check if request is in only_from
if(!empty($args['only_from']) && !empty($remoteHost) && !in_array($remoteHost, explode(',', $args['only_from'])))
{
	echo 'This host is not allowed to authenticate using this PAM module.'.PHP_EOL;
	exit(2);
}

// unpack assertion
$xmlSrc = base64_decode($xmlSrc, true);
if($xmlSrc === false)
{
	echo 'No valid Assertion given: Invalid characters in Base64 string'.PHP_EOL;
	exit(3);
}
$xml = false;
$xml = @gzuncompress($xmlSrc);
if($xml === false)
{
	echo 'No valid Assertion given: Uncompress failed'.PHP_EOL;
	exit(3);
}

// Load assertion XML in lightSAML
try
{
	$assDeserializer = new \LightSaml\Model\Context\DeserializationContext();
	$assDeserializer->getDocument()->loadXML($xml);
	// Check if it's a response (for instance from mod_auth_mellon with MellonDumpResponse On),
	// otherwise, treat it as assertion
	if($assDeserializer->getDocument()->firstChild->localName === "Response")
	{
		$response = new \LightSaml\Model\Protocol\Response();
		$response->deserialize($assDeserializer->getDocument()->firstChild, $assDeserializer);
		$assertion = $response->getFirstAssertion();
	}
	else
	{
		$assertion = new \LightSaml\Model\Assertion\Assertion();
		$assertion->deserialize($assDeserializer->getDocument()->firstChild, $assDeserializer);
	}
}
catch(\Exception $e)
{
	echo 'An error occured while parsing the Assertion: '.$e->getMessage().PHP_EOL;
	exit(3);
}

// validate signature
if(!empty($args['idp']))
{
	$certs = array();

	// load all signing keys from given IdP metadata
	foreach($args['idp'] as $idpMetadataXml)
	{
		try
		{
			$entityDescriptor = \LightSaml\Model\Metadata\EntityDescriptor::load($idpMetadataXml);
			$entityId = $entityDescriptor->getEntityID();
			$idpSsoDescriptor = $entityDescriptor->getFirstIdpSsoDescriptor();
			if(isset($idpSsoDescriptor))
			{
				$idpSigningKeyDescriptors = $idpSsoDescriptor->getAllKeyDescriptorsByUse(\LightSaml\Model\Metadata\KeyDescriptor::USE_SIGNING);
				if(!empty($idpSigningKeyDescriptors))
				{
					$certs[$entityId] = array();
					foreach($idpSigningKeyDescriptors as $keyDescriptor)
					{
						$certs[$entityId][] = $keyDescriptor->getCertificate();
					}
				}
			}
		}
		catch(\Exception $e)
		{
			echo 'An error occured while loading IdP metadata.'.PHP_EOL;
			exit(4);
		}
	}

	// validate signature against given IdP certs
	try
	{
		$signature = $assertion->getSignature();
		$issuer = $assertion->getIssuer();
		$idpEntityId = $issuer->getValue();
		if(isset($signature))
		{
			if(isset($certs[$idpEntityId]))
			{
				$ok = false;
				foreach($certs[$idpEntityId] as $cert)
				{
					$pubKey = \LightSaml\Credential\KeyHelper::createPublicKey($cert);
					$ok = $signature->validate($pubKey);
					if($ok) break;
				}
				// no given cert did validate
				if(!$ok)
				{
					echo 'No corresponding certificate for "'.$idpEntityId.'" could validate the given signature.'.PHP_EOL;
					exit(6);
				}
			}
			else
			{
				echo 'No corresponding certificate for "'.$idpEntityId.'" was found in the IdP metadata.'.PHP_EOL;
				exit(5);
			}
		}
		else
		{
			// no signature given, just check if any of our IdPs is the issuer
			if(!isset($certs[$idpEntityId]))
			{
				echo '"'.$idpEntityId.'" was not found in the given IdPs.'.PHP_EOL;
				exit(6);
			}
		}
	}
	catch(\Exception $e)
	{
		echo 'An error occured while validating the Assertion signature.'.PHP_EOL;
		exit(4);
	}
}

// validate assertion
try
{
	$nameIdValidator = new \LightSaml\Validator\Model\NameId\NameIdValidator();
	$assertionValidator = new \LightSaml\Validator\Model\Assertion\AssertionValidator(
		$nameIdValidator,
		new \LightSaml\Validator\Model\Subject\SubjectValidator($nameIdValidator),
		new \LightSaml\Validator\Model\Statement\StatementValidator()
	);
	$assertionTimeValidator = new \LightSaml\Validator\Model\Assertion\AssertionTimeValidator();

	$assertionValidator->validateAssertion($assertion);
	if((bool)$args['saml_check_timeframe'])
	{
		$assertionTimeValidator->validateTimeRestrictions(
			$assertion,
			time(),
			(isset($args['grace']) && (int)$args['grace'] != 0) ? (int)$args['grace'] : 600
		);
	}
}
catch(\LightSaml\Error\LightSamlValidationException $e)
{
	echo 'The Assertion could not be validated: '.$e->getMessage().PHP_EOL;
	exit(7);
}
catch(\Exception $e)
{
	echo 'An error occured while validating the Assertion.'.PHP_EOL;
	exit(4);
}

// match trusted_sp
if(!empty($args['trusted_sp']))
{
	try
	{
		$conditions = $assertion->getConditions();
		if(isset($conditions))
		{
			$audienceRestrictions = $conditions->getAllAudienceRestrictions();
			if(!empty($audienceRestrictions))
			{
				$ok = false;
				foreach($audienceRestrictions as $audienceRestriction)
				{
					foreach($args['trusted_sp'] as $spEntityId)
					{
						$ok = $audienceRestriction->hasAudience($spEntityId);
						if($ok) break 2;
					}
				}
				// trusted_sp's are not in the audience
				if(!$ok)
				{
					echo 'No trusted_sp could be found in the given Assertion.'.PHP_EOL;
					exit(6);
				}
			}
		}
	}
	catch(\Exception $e)
	{
		echo 'An error occured while checking the audience of the Assertion.'.PHP_EOL;
		exit(4);
	}
}

// match attributes
try
{
	$attributeStatements = $assertion->getAllAttributeStatements();
	if(isset($attributeStatements))
	{
		$ok = false;
		foreach($attributeStatements as $attributeStatement)
		{
			$attributes = $attributeStatement->getAllAttributes();
			foreach($attributes as $attribute)
			{
				if($attribute->getName() === $args['userid'] || $attribute->getFriendlyName() === $args['userid'])
				{
					$ok = in_array($pamUser, $attribute->getAllAttributeValues());
					if($ok) break 2;
				}
			}
		}
		// there was no attribute with the name of userid or it didn't match
		if(!$ok)
		{
			echo 'Assertion did not contain "'.$args['userid'].'" attribute or it did not match with the PAM username.'.PHP_EOL;
			exit(6);
		}
	}
	else
	{
		echo 'Assertion contained no attributes. We need at least "'.$args['userid'].'".'.PHP_EOL;
		exit(6);
	}
}
catch(\Exception $e)
{
	echo 'An error occured while checking the userid attribute of the Assertion.'.PHP_EOL;
	exit(4);
}

exit(0);
