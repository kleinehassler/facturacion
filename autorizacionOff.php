<?php

$wsdl = "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantes?wsdl";
//$wsdl = "https://cel.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantes?wsdl";

$path = __DIR__;
$file = $path."/xml_firmado/RETC_001-001-000000049.xml";
$file = file_get_contents($file);
$xml = simplexml_load_string($file);
$clave_acceso = $xml->infoTributaria->claveAcceso;

$options = [
        'exceptions'=>true,
        'trace'=>1,
        'cache_wsdl'=>WSDL_CACHE_NONE,
        'stream_context' => stream_context_create([
            "ssl"=>[
                "verify_peer"=>false, 
                "verify_peer_name"=>false,
                'crypto_method' => STREAM_CRYPTO_METHOD_TLS_CLIENT
            ]
        ])
];

$client = new SoapClient($wsdl, $options);
$client->autorizacionComprobante(["claveAccesoComprobante" => $clave_acceso]);
header("Content-type: text/xml; charset=utf-8");
echo '<?xml version="1.0" encoding="UTF-8"?>';
echo $client->__getLastResponse();