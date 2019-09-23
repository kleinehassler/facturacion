<?php
//include 'Curl.php';

$wsdl = "https://celcer.sri.gob.ec/comprobantes-electronicos-ws/AutorizacionComprobantes?wsdl";
$path = __DIR__;
$file = $path."/xml/0309201907099263700500110010010000000710000007112.xml";
$file = file_get_contents($file);
$xml = simplexml_load_string($file);
$clave_acceso = $xml->infoTributaria->claveAcceso;

/*
$xml_envio = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:ec=\"http://ec.gob.sri.ws.autorizacion\">";
$xml_envio .="<soapenv:Header/>";
$xml_envio .="<soapenv:Body>";
$xml_envio .="<ec:autorizacionComprobante>";
$xml_envio .="<claveAccesoComprobante>{$clave_acceso}</claveAccesoComprobante>";
$xml_envio .="</ec:autorizacionComprobante>";
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
*/
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