<?php
include 'xades.php';

class FirmaElectronica{
    private $config; ///< Configuración de la firma electrónica
    private $certs; ///< Certificados digitales de la firma
    private $data; ///< Datos del certificado digial
    private $pkey;

    public function __construct(array $config = [],$password, $token, $pkey = NULL) {     
        $this->pkey = $pkey;

        $this->config = array_merge([
            'file' => $token,
            'pass' => $password,
            'data' => null,
            'wordwrap' => 76,
            'serial' => null,
        ], $config); 

        // cargar firma electrónica desde el contenido del archivo .p12      
        if (!$this->config['data'] and $this->config['file']) {
            if (is_readable($this->config['file'])) {
                $this->config['data'] = file_get_contents($this->config['file']);
            } else {
                die('Archivo de la firma electronica '.basename($this->config['file']).' no puede ser leído');
            }
        } 
        // leer datos de la firma electrónica
        if ($this->config['data'] and openssl_pkcs12_read($this->config['data'], $this->certs, $this->config['pass'])===false) {
            die('No fue posible leer los datos de la firma electrónica (verificar la contraseña)');
        }            
        $this->data = openssl_x509_parse($this->certs['extracerts'][0]);
     
        $this->config['serial'] = $this->data['serialNumber'];
        unset($this->config['data']);

    }         
    public function getID() {          
        $certificado = $this->certs['extracerts'][0];
        $certificado = str_replace('-----BEGIN CERTIFICATE-----', "", $certificado);
        $certificado = str_replace('-----END CERTIFICATE-----', "", $certificado);
        $certificado = str_replace("\n", "", $certificado);
        $certificado = str_split($certificado, 76);
        $certificado = implode("\n", $certificado);
        $certificado_b64 = str_replace("\n", "", $certificado);
        $cert = base64_encode(hash("sha1", base64_decode($certificado_b64), true));
        return $cert;
    }
 
    public function getCertificate($clean = false) {
        if ($clean) {
            $cert = $this->certs['extracerts'][0];            
            $cert = str_replace("-----BEGIN CERTIFICATE-----\n", "", $cert);
            $cert = str_replace("-----END CERTIFICATE-----\n", "", $cert);
            $cert = str_replace("\n", "", $cert);            
            $cert = wordwrap($cert, $this->config['wordwrap'], "\n", true);
            return $cert;
        } else {
            return $this->certs['extracerts'][0];
        }       
    }
    
    public function getModulus() {
        if($this->pkey){
            $details = openssl_pkey_get_details(openssl_pkey_get_private($this->pkey[1]));
        }else{
            $details = openssl_pkey_get_details(openssl_pkey_get_private($this->certs['pkey']));
        }
        return wordwrap(base64_encode($details['rsa']['n']), $this->config['wordwrap'], "\n", true);
    }

    public function getData() {
        return $this->data;
    }    

    public function getExponent() {
        if($this->pkey){
            $details = openssl_pkey_get_details(openssl_pkey_get_private($this->pkey[1]));
        }else{
            $details = openssl_pkey_get_details(openssl_pkey_get_private($this->certs['pkey']));
        }
        return wordwrap(base64_encode($details['rsa']['e']), $this->config['wordwrap'], "\n", true);
    }             

    public function p_obtener_aleatorio() {
        return floor(rand() * 999000) + 990;    
    }

    public function sign($data, $signature_alg = OPENSSL_ALGO_SHA1) {   
        $signature = null;
        if (openssl_sign($data, $signature, $this->pkey[1], $signature_alg)==false) {
            return $this->error('No fue posible firmar los datos');
        }
        return base64_encode($signature); 
    }

    private function normalizeCert($cert){
        if (strpos($cert, '-----BEGIN CERTIFICATE-----')===false) {
            $body = trim($cert);
            $cert = '-----BEGIN CERTIFICATE-----'."\n";
            $cert .= $body."\n";
            $cert .= '-----END CERTIFICATE-----'."\n";
        }
        return $cert;
    }

    public function verify($data, $signature, $pub_key = null, $signature_alg = OPENSSL_ALGO_SHA1)
    {
        $pub_key = $this->normalizeCert($pub_key);
        $signature = trim($signature);
        return openssl_verify($data, base64_decode($signature), $pub_key, $signature_alg) == 1 ? true : false;
    }

    public function verifyXML($xml_data, $tag = null)
    {
        $doc = new DOMDocument('1.0', 'UTF-8');
        $doc->loadXML($xml_data);
        // preparar datos que se verificarán
        $SignaturesElements = $doc->documentElement->getElementsByTagName('Signature');
        $Signature = $doc->documentElement->removeChild($SignaturesElements->item($SignaturesElements->length-1));
        $SignedInfo = $Signature->getElementsByTagName('SignedInfo')->item(0);
        $SignedInfo->setAttribute('xmlns', $Signature->getAttribute('xmlns'));
        $signed_info = $doc->saveHTML($SignedInfo);
        $signature = $Signature->getElementsByTagName('SignatureValue')->item(0)->nodeValue;
        $pub_key = $Signature->getElementsByTagName('X509Certificate')->item(0)->nodeValue;
        // verificar firma
        if (!$this->verify($signed_info, $signature, $pub_key))
            return false;
        // verificar digest
        $digest_original = $Signature->getElementsByTagName('DigestValue')->item(0)->nodeValue;
        if ($tag) {
            $digest_calculado = base64_encode(sha1($doc->documentElement->getElementsByTagName($tag)->item(0)->C14N(), true));
        } else {
            $digest_calculado = base64_encode(sha1($doc->C14N(), true));
        }
        return $digest_original == $digest_calculado;
    }

    public function signXML($xml, $reference = '', $tag = null, $xmlns_xsi = false,$tipoDocumento,$clave) {
        $formatXades = getXades();                
        $CertDigest = $this->getID();
        $data = $this->getData();  
        $serial = 'CN='.$data['issuer']['CN'].',L='.$data['issuer']['L'].',OU='.$data['issuer']['OU'].',O='.$data['issuer']['O'].',C='.$data['issuer']['C'];        
        $serialNumber = $this->config['serial'];
        $doc = new DOMDocument('1.0', 'UTF-8');
        $doc->loadXML($xml);
        if (!$doc->documentElement) {
            return 'No fue posible obtener el documentElement desde el XML a firmar';
        }
        //$digest = base64_encode(pack("H*", sha1( $doc->C14N() )));

        //$digestComprobante = base64_encode(sha1($doc->saveHTML($doc->getElementsByTagName($tipoDocumento)->item(0)),true));
        $tempXml = $doc->saveHTML($doc->getElementsByTagName($tipoDocumento)->item(0));
        $digestComprobante = base64_encode(pack("H*", sha1($tempXml)));
        $fragment = $doc->createDocumentFragment();
        $fragment->appendXML($formatXades);
        $doc->getElementsByTagName($tipoDocumento)->item(0)->appendChild($fragment);
        $doc->formatOutput = TRUE;        
        date_default_timezone_set('America/Guayaquil');        
        $timestamp = new DateTime();
        $fecha =  $timestamp->format('c'); // Returns ISO8601 el formato propio xades
        $doc->getElementsByTagName('SigningTime')->item(0)->nodeValue = $fecha;
        $doc->getElementsByTagName('DigestValue')->item(3)->nodeValue = $CertDigest;

        $doc->getElementsByTagName('X509IssuerName')->item(0)->nodeValue = $serial;
        $doc->getElementsByTagName('X509SerialNumber')->item(0)->nodeValue = $serialNumber;        
        //$digestSignedProperties = base64_encode(sha1($doc->getElementsByTagName('SignedProperties')->item(0)->C14N(), true));  
        $digestSignedProperties = base64_encode(pack("H*", sha1($doc->getElementsByTagName('SignedProperties')->item(0)->C14N())));      
        $doc->getElementsByTagName('DigestValue')->item(0)->nodeValue = $digestSignedProperties;
        $doc->getElementsByTagName('Modulus')->item(0)->nodeValue = $this->getModulus();
        $doc->getElementsByTagName('Exponent')->item(0)->nodeValue = $this->getExponent();
        $doc->getElementsByTagName('X509Certificate')->item(0)->nodeValue = $this->getCertificate(true);
        //$digestCertificate = base64_encode(sha1($doc->getElementsByTagName('KeyInfo')->item(0)->C14N(), true)); 
        $keyInfo = $doc->getElementsByTagName('KeyInfo')->item(0)->C14N(); 
        $digestCertificate = base64_encode(pack("H*", sha1($keyInfo)));
        $doc->getElementsByTagName('DigestValue')->item(1)->nodeValue = $digestCertificate;        
        $doc->getElementsByTagName('DigestValue')->item(2)->nodeValue = $digestComprobante;   
        $dataToSign = $doc->getElementsByTagName('SignedInfo')->item(0)->C14N();
        $firma = $this->sign($dataToSign);
        $signature = wordwrap($firma, $this->config['wordwrap'], "\n", true);
        $doc->getElementsByTagName('SignatureValue')->item(0)->nodeValue = $signature;
        //$pub_key  = openssl_pkey_get_details(openssl_pkey_get_public ($this->certs['cert'] ));
        //$private_key = openssl_pkey_get_details(openssl_get_privatekey($this->certs['pkey']));       

        return $doc->saveXML();
    }   
}