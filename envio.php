<?php
include 'Curl.php';

$wsdl = "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl";
//$wsdl = "https://cel.sri.gob.ec/comprobantes-electronicos-ws/RecepcionComprobantesOffline?wsdl";

$path = __DIR__;
$file = $path."/xml_firmado/RETC_001-001-000000049.xml";
$file = file_get_contents($file);
$xml = $file;
//$xml = simplexml_load_string($file);
//$clave_acceso = $xml->infoTributaria->claveAcceso;


$xml_envio = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ec=\"http://ec.gob.sri.ws.recepcion\">";
$xml_envio .="<soapenv:Header/>";
$xml_envio .="<soapenv:Body>";
$xml_envio .="<ec:validarComprobante>";
$xml_envio .="<xml>".base64_encode($xml)."</xml>";
$xml_envio .="</ec:validarComprobante>";
$xml_envio .="</soapenv:Body>";
$xml_envio .="</soapenv:Envelope>";


$html = Curl::GetPage([
    "url" => $wsdl,
    "method" => "POST",
    "requestHeaders" => ["Content-Type" => "text/xml"],
    "data" => $xml_envio
]);

header("Content-type: text/xml; charset=utf-8");
echo '<?xml version="1.0" encoding="UTF-8"?>';
echo $html;

/*
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
$client->validarComprobante(["xml" => $xml]);
header("Content-type: text/xml; charset=utf-8");
echo '<?xml version="1.0" encoding="UTF-8"?>';
echo $client->__getLastResponse();
*/