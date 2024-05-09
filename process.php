<?php

require_once('saml.php');

function generateRequest($settings_info)

{

    $authn_request_binding = $settings_info['authn_request_binding'];

    $name_id_format = $settings_info['name_id_format'];

    $authn_context = $settings_info['authn_context'];

    $sp_entity_id = $settings_info['sp_entity_id'];

    $sp_acs_url = $settings_info['sp_acs_url'];

    $private_key = $settings_info['sp_private_key'];

    $idp_sso_url = $settings_info['idp_sso_url'];

    $xmlstr = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"

    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="' . '_' . sha1(uniqid(mt_rand(), true)) . '" Version="2.0" IssueInstant="' . date('Y-m-dTH:i:sZ') . '" Destination="' . $idp_sso_url . '" ProtocolBinding="' . $authn_request_binding . '" AssertionConsumerServiceURL="' . $sp_acs_url . '">

    <saml:Issuer>' . $sp_entity_id . '</saml:Issuer>

    <samlp:NameIDPolicy Format="' . $name_id_format . '" AllowCreate="true"/>

    <samlp:RequestedAuthnContext Comparison="exact">

    <saml:AuthnContextClassRef>' . $authn_context . '</saml:AuthnContextClassRef>

    </samlp:RequestedAuthnContext>

    </samlp:AuthnRequest>';

    $doc = new DOMDocument();

    $doc->loadXML($xmlstr);

    $objXMLSecDSig = new XMLSecurityDSig();

    $objXMLSecDSig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);

    $objXMLSecDSig->addReference($doc, XMLSecurityDSig::SHA1, array('<http://www.w3.org/2000/09/xmldsig#enveloped-signature>'), array('force_uri' => true));

    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));

    $objKey->loadKey($private_key, true);

    $objXMLSecDSig->sign($objKey);

    $xmlDoc = $objXMLSecDSig->createEnvelope();

    $authnRequest = $xmlDoc->saveXML();

    return $authnRequest;
}

function processResponse($settings_info, $saml_response)

{

    $response_binding = $settings_info['response_binding'];

    $sp_entity_id = $settings_info['sp_entity_id'];

    $sp_slo_url = $settings_info['sp_slo_url'];

    $sp_private_key = $settings_info['sp_private_key'];

    $idp_entity_id = $settings_info['idp_entity_id'];

    $idp_sso_url = $settings_info['idp_sso_url'];

    $idp_x509_cert = $settings_info['idp_x509_cert'];

    $xmlDoc = new DOMDocument();

    $xmlDoc->loadXML($saml_response);

    $objXMLSecDSig = new XMLSecurityDSig();

    $objDSig = $objXMLSecDSig->locateSignature($xmlDoc);

    $objXMLSecDSig->canonicalizeSignedInfo();

    $objXMLSecDSig->idKeys = array('ID');

    $objXMLSecDSig->idNS = array('urn:oasis:names:tc:SAML:2.0:assertion');

    $retVal = $objXMLSecDSig->validateReference();

    if (!$retVal) {

        throw new Exception('Invalid Signature');
    }

    $objKey = new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, array('type' => 'private'));

    $objKey->loadKey($sp_private_key, true);

    $objXMLSecDSig->verify($objKey);

    $saml_response_dom = new DOMDocument();

    $saml_response_dom->loadXML($saml_response);

    $assertions = $saml_response_dom->getElementsByTagName('Assertion');

    if ($assertions->length < 1) {

        throw new Exception('No assertions found in response.');
    }

    $assertion = $assertions->item(0);

    $issuer = $assertion->getElementsByTagName('Issuer')->item(0)->nodeValue;

    if ($issuer !== $idp_entity_id) {

        throw new Exception('Invalid issuer in response');
    }

    $subject = $assertion->getElementsByTagName('Subject')->item(0);

    $name_id = $subject->getElementsByTagName('NameID')->item(0)->nodeValue;

    $session_index = $assertion->getElementsByTagName('AuthnStatement')->item(0)->getAttribute('SessionIndex');

    $attributes = array();

    $attribute_statements = $assertion->getElementsByTagName('AttributeStatement');

    if ($attribute_statements->length > 0) {

        $attribute_statement = $attribute_statements->item(0);

        foreach ($attribute_statement->childNodes as $node) {

            if ($node->nodeType == XML_ELEMENT_NODE) {

                $attributes[$node->getAttribute('Name')] = $node->nodeValue;
            }
        }
    }

    $response = array(

        'name_id' => $name_id,

        'session_index' => $session_index,

        'attributes' => $attributes,

    );

    return $response;
}

function redirect($url)

{

    header('Location: ' . $url);

    exit();
}

if (!empty($_GET['SAMLResponse'])) {

    $response = processResponse($settings_info, $_GET['SAMLResponse']);

    // Process the authenticated user

    // ...

    redirect($sp_slo_url);
} else {

    $authnRequest = generateRequest($settings_info);

    redirect($idp_sso_url . '?SAMLRequest=' . urlencode(base64_encode($authnRequest)));
}
