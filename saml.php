<?php

$idp_entity_id = '<https://idp.example.com/metadata>';
$idp_sso_url = '<https://idp.example.com/sso>';
$idp_slo_url = '<https://idp.example.com/slo>';
$idp_x509_cert = 'MIICizCCAfQCCQCY...';

$sp_entity_id = '<https://sp.example.com/metadata>';
$sp_acs_url = '<https://sp.example.com/acs>';
$sp_slo_url = '<https://sp.example.com/slo>';
$sp_x509_cert = 'MIICizCCAfQCCQCY...';
$sp_private_key = 'MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJH2LlNQy8...';

$authn_request_binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';

$response_binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';

$name_id_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';

$authn_context = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

$settings_info = [
    'idp_entity_id' => $idp_entity_id,
    'idp_sso_url' => $idp_sso_url,
    'idp_slo_url' => $idp_slo_url,
    'idp_x509_cert' => $idp_x509_cert,
    'sp_entity_id' => $sp_entity_id,
    'sp_acs_url' => $sp_acs_url,
    'sp_slo_url' => $sp_slo_url,
    'sp_x509_cert' => $sp_x509_cert,
    'sp_private_key' => $sp_private_key,
    'authn_request_binding' => $authn_request_binding,
    'response_binding' => $response_binding,
    'name_id_format' => $name_id_format,
    'authn_context' => $authn_context,
];