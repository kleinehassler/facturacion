<?php

$xml = "./xml/RETC_001-001-000000049.xml";
//$cert = "./firma/orodelti/0992129824001.p12";
$cert = "./firma/goddcorp/0992637005001.p12";
$path = "./xml_firmado/";
$name = trim(basename($xml));
//$pass = "Orodelti2018";
$pass = "cc19540AB";
$file_java = "./helpers/java/sri.jar";
$command = "java -jar {$file_java} {$cert} {$pass} {$xml} {$path} {$name}";
exec($command, $output);

if(is_array($output)){
    foreach ($output as $key => $txt) {
        echo $txt."</br>";
    }
}else{
    echo $output;
}