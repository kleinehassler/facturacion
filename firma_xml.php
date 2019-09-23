<?php
include 'helpers/Firma.php';
include 'helpers/FirmaElectronica.php';
include 'helpers/Pem.php';

include_once('helpers/phpseclib/Crypt/RSA.php');
include_once('helpers/phpseclib/File/X509.php');
include_once('helpers/phpseclib/Math/BigInteger.php');     

function object2array($object){
    return json_decode(json_encode($object), TRUE); 
}

$path = __DIR__."/xml/RETC_001-001-000000049.xml";
$cert = __DIR__."/firma/goddcorp/0992637005001.p12";
$pem_path = __DIR__."/firma/goddcorp/key.pem";
$pem = new Pem($pem_path);
$pem = $pem->privateKeys();
/*
$firma = new Firma($path, $cert);
$xml = $firma->firmar_documento();
*/
$path_save = "./xml_firmado/";
//$file = $path_save.$firma->getFileName();
//@file_put_contents($file, $xml);
$file = trim(file_get_contents($path));
$xml = simplexml_load_string($file);
$xml_keys = array_keys(object2array($xml));
$tipoComprobante = lcfirst(str_replace("info", "", @$xml_keys[2]));
$tipoComprobante = str_replace("comp", "comprobante", $tipoComprobante);
/*
$firma = new Firma($path, $cert, $pem);
$firma_xml = $firma->firmar_documento();
$firma_file = $path_save.$firma->getFileName();
@file_put_contents($firma_file, $firma_xml);
*/
$firma = new FirmaElectronica($config = [],"cc19540AB", $cert, $pem);              
$content = $firma->signXML($file,'', null, false,$tipoComprobante, "cc19540AB");
//var_dump($content);
//$content = iconv("CP1257","UTF-8", $content);
@file_put_contents($path_save.trim(basename($path)), trim($content));
/*$file = "./xml_firmado/RETC_001-001-000000049.xml";
$file = file_get_contents($file);
$verify = $firma->verifyXML($file);
var_dump($verify);
*/
echo "XML FIRMADO";